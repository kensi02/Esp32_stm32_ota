#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"

#include "nvs.h"
#include "nvs_flash.h"

#include "sodium/crypto_hash_sha256.h"
//****For SPIFFS**************//
#include <stdio.h>
#include <string.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_err.h"
#include "esp_spiffs.h"
//****************************//

//#define Ver_A

#define EXAMPLE_WIFI_SSID "wifi_ssid"//CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS "wifi_pass"//CONFIG_WIFI_PASSWORD
/*#ifdef Ver_A
#define ESP_FW_URL "http://<SERVER_NAME>:7777/firmware_esp32_B.bin"//CONFIG_FIRMWARE_UPG_URL
#else
#define ESP_FW_URL "http://<SERVER_NAME>:7777/firmware_esp32_A.bin"//CONFIG_FIRMWARE_UPG_URL
#endif*/
#define STM_FW_URL "http://<SERVER_NAME>:7777/firmware_stm32.bin"//CONFIG_FIRMWARE_UPG_URL
#define ESP_FW_URL "http://<SERVER_NAME>:7777/firmware_esp32.bin"//CONFIG_FIRMWARE_UPG_URL
#define BUFFSIZE 1024

static const char *TAG_ota = "OTA";
static const char *TAG_fs = "SPIFFS";
static const char *TAG_http = "http_log";
/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = { 0 };
static char signature[65] = { 0 };
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
//extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

static void spiffs_init(void)
{
    ESP_LOGI(TAG_fs, "Initializing SPIFFS");

        esp_vfs_spiffs_conf_t conf = {
          .base_path = "/spiffs",
          .partition_label = NULL,
          .max_files = 5,
          .format_if_mount_failed = true
        };
    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK)
    {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG_fs, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG_fs, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG_fs, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }
    ESP_LOGI(TAG_fs, "Filesystem mounted ok");
    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG_fs, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
    }
    else
    {
        ESP_LOGI(TAG_fs, "Partition size: total: %d, used: %d", total, used);
    }
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initialise_wifi(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_LOGI(TAG_ota, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static void http_cleanup(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

static void __attribute__((noreturn)) task_fatal_error()
{
    ESP_LOGE(TAG_ota, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);
    while (1) {;}
}

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG_http, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG_http, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG_http, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            //ESP_LOGD(TAG_http, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            if(strcmp(evt->header_key,"Signature") == 0)
            {
                //ESP_LOGI(TAG_http, "We've goten signature: %s", evt->header_value);
                memcpy(signature, evt->header_value, 65);
                ESP_LOGI(TAG_http, "signature is : %s", signature);
            }
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG_http, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG_http, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGD(TAG_http, "HTTP_EVENT_DISCONNECTED");
            break;
    }
    return ESP_OK;
}

void arr2str_hex(unsigned char* in, char* out, unsigned int inLen)
{
    char temp[17] = {0};
    for(int i = 0; i < inLen; i++)
    {
        if(in[i] <= 0x0f) {strcat(out, "0");}
        itoa(in[i], temp, 16);
        strcat(out, temp);
        memset(temp, 0, 17);
    }
}

static void ota_example_task(void *pvParameter)
{
    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0 ;
    const esp_partition_t *update_partition = NULL;
    int binary_file_length = 0;
    FILE* file;
    uint8_t calculated[32] = {0};
    char calculated_str[65] = {0};
    uint8_t buff[BUFFSIZE];
    unsigned int cnt = 0;

    ESP_LOGI(TAG_ota, "Starting OTA example...");

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (configured != running) {
        ESP_LOGW(TAG_ota, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
                 configured->address, running->address);
        ESP_LOGW(TAG_ota, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG_ota, "Running partition type %d subtype %d (offset 0x%08x)",
             running->type, running->subtype, running->address);
//*********************Stm update part**************************
esp_http_client_config_t config = {
        .url = STM_FW_URL,
        .cert_pem = (char *)server_cert_pem_start,
        .event_handler = _http_event_handler
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG_http, "Failed to initialise HTTP connection");
        task_fatal_error();
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_http, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);

    file = fopen("/spiffs/fw.bin", "wb");
    if (file == NULL) {
        ESP_LOGE(TAG_fs, "Failed to open file for writing");
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    while (1) {
        int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        if (data_read < 0) {
            ESP_LOGE(TAG_http, "Error: SSL data read error");
            http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            fwrite(ota_write_data, sizeof(char), data_read, file);
            binary_file_length += data_read;
            ESP_LOGD(TAG_ota, "Written stm image length %d", binary_file_length);
            } else if (data_read == 0) {
                fclose(file);
                ESP_LOGI(TAG_ota, "Connection closed,all data received");
                break;
        }
    }
    ESP_LOGI(TAG_ota, "Total Write binary data length : %d", binary_file_length);
    file = fopen("/spiffs/fw.bin", "rb");
    if (file == NULL) {
            ESP_LOGE(TAG_fs, "Failed to open file for writing");
            esp_http_client_cleanup(client);
            task_fatal_error();
        }
    crypto_hash_sha256_state stateStm;
    crypto_hash_sha256_init(&stateStm);
    do
    {
        //cnt = (fread(buff, sizeof(buff), 1, file));
        cnt = (fread(buff, 1, sizeof(buff), file));
        crypto_hash_sha256_update(&stateStm, buff, cnt); 
    }while (cnt > 0);
    crypto_hash_sha256_final(&stateStm, calculated);
    fclose(file);
    
    arr2str_hex(calculated, calculated_str, 32);
    ESP_LOGI(TAG_fs, "calculated_str: %s", calculated_str);
    if(strcmp(calculated_str, signature) == 0) ESP_LOGI(TAG_fs, "Signature check ok.");
    else
    {
        ESP_LOGI(TAG_fs, "Signature check error.");
        http_cleanup(client);
        task_fatal_error();
    }
    printf("\n\nHere we are going to update STM32 target.\n");
    for(int i = 0; i < 20; i++)
    {
        //vTaskDelay(1000 / portTICK_PERIOD_MS);
        printf(".");
        vTaskDelay( pdMS_TO_TICKS(100));
    }
    printf("\nSTM32 target update complite.\n\n");
    esp_http_client_close(client);
    http_cleanup(client);

//*********************ESP update part**************************
    binary_file_length = 0;
    memset(calculated_str, 0, 65);
    memset(calculated, 0, 32);
    memset(buff, 0, BUFFSIZE);
    cnt = 0;
    /*config = {
        .url = ESP_FW_URL,
        .cert_pem = (char *)server_cert_pem_start,
        .event_handler = _http_event_handler
    };*/
    config.url = ESP_FW_URL;
    client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG_http, "Failed to initialise HTTP connection");
        task_fatal_error();
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_http, "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);

    file = fopen("/spiffs/fw.bin", "wb");
    if (file == NULL) {
        ESP_LOGE(TAG_fs, "Failed to open file for writing");
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    while (1) {
        int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        if (data_read < 0) {
            ESP_LOGE(TAG_http, "Error: SSL data read error");
            http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            fwrite(ota_write_data, sizeof(char), data_read, file);
            binary_file_length += data_read;
            ESP_LOGD(TAG_ota, "Written image length %d", binary_file_length);
            } else if (data_read == 0) {
                fclose(file);
                ESP_LOGI(TAG_ota, "Connection closed,all data received");
                break;
        }
    }
    ESP_LOGI(TAG_ota, "Total Write binary data length : %d", binary_file_length);
    file = fopen("/spiffs/fw.bin", "rb");
    if (file == NULL) {
            ESP_LOGE(TAG_fs, "Failed to open file for writing");
            esp_http_client_cleanup(client);
            task_fatal_error();
        }
    crypto_hash_sha256_state stateEsp;
    crypto_hash_sha256_init(&stateEsp);
    do
    {
        //cnt = (fread(buff, sizeof(buff), 1, file));
        cnt = (fread(buff, 1, sizeof(buff), file));
        crypto_hash_sha256_update(&stateEsp, buff, cnt); 
    }while (cnt > 0);
    crypto_hash_sha256_final(&stateEsp, calculated);
    fclose(file);
    arr2str_hex(calculated, calculated_str, 32);
    ESP_LOGI(TAG_fs, "calculated_str: %s", calculated_str);
    if(strcmp(calculated_str, signature) == 0) ESP_LOGI(TAG_fs, "Signature check ok.");
    else
    {
        ESP_LOGI(TAG_fs, "Signature check error.");
        http_cleanup(client);
        task_fatal_error();
    }
    update_partition = esp_ota_get_next_update_partition(NULL);
    ESP_LOGI(TAG_ota, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);
    assert(update_partition != NULL);

    err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_ota, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }
    ESP_LOGI(TAG_ota, "esp_ota_begin succeeded");
    file = fopen("/spiffs/fw.bin", "rb");
    if (file == NULL) {
            ESP_LOGE(TAG_fs, "Failed to open file for writing");
            esp_http_client_cleanup(client);
            task_fatal_error();
        }
    memset(ota_write_data, 0, BUFFSIZE);
    while(1)
    {
        int data_read = fread(ota_write_data, 1, BUFFSIZE, file);
        if (data_read > 0) 
        {
            err = esp_ota_write(update_handle, (const void *)ota_write_data, data_read);
            if (err != ESP_OK) {
                ESP_LOGE(TAG_ota, "Update firmwere error!");
                task_fatal_error();
            }
        } 
        else 
        {
            fclose(file);
            ESP_LOGI(TAG_ota, "EOF, file have been closed.");
            break;
        }
    }
    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_ota, "esp_ota_end failed! : '%s'", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_ota, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }
    ESP_LOGE(TAG_ota, "Prepare to restart system! Restart after 10 sec.");
    vTaskDelay(10000 / portTICK_PERIOD_MS);
    esp_restart();
    return ;
}

void app_main()
{
    //esp_log_level_set("*", ESP_LOG_ERROR);
    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );
    spiffs_init();
    initialise_wifi();
    /* Wait for the callback to set the CONNECTED_BIT in the
       event group.*/
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                        false, true, portMAX_DELAY);
    ESP_LOGI(TAG_ota, "Connect to Wifi ! Start to Connect to Server....");
    /*char in_char = '\0';
    vTaskDelay(7000 / portTICK_PERIOD_MS);
    printf("\n\n\n");
    #ifdef Ver_A
    printf("ESP Firmware 'A'.\n");
    #else
    printf("ESP Firmware 'B'.\n");
    #endif
    printf("Please enter 's' to start ota.\n");
    do{
        scanf("%c", &in_char);
        }while (in_char != 's');*/
    xTaskCreate(&ota_example_task, "ota_example_task", 8192, NULL, 4, NULL);
}

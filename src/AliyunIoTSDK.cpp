
#include "AliyunIoTSDK.h"
#include <PubSubClient.h>
#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32C3)
#include <mbedtls/md.h>
#else
#include <SHA256.h> // Crypto
#endif

#define CHECK_INTERVAL 10000
#define MESSAGE_BUFFER_SIZE 10
#define RETRY_CRASH_COUNT 5

static String deviceName ;
static String productKey ;
static String deviceSecret ;
static String region ;

struct DeviceProperty
{
    String key;
    String value;
};

DeviceProperty PropertyMessageBuffer[MESSAGE_BUFFER_SIZE];

#define MQTT_PORT 1883

#define SHA256HMAC_SIZE 32
#define DATA_CALLBACK_SIZE 20

#define ALINK_BODY_FORMAT "{\"id\":\"123\",\"version\":\"1.0\",\"method\":\"thing.event.property.post\",\"params\":%s}"
#define ALINK_EVENT_BODY_FORMAT "{\"id\": \"123\",\"version\": \"1.0\",\"params\": %s,\"method\": \"thing.event.%s.post\"}"

static unsigned long lastMs = 0;
static int retry_count = 0;

static PubSubClient *client = NULL;

char AliyunIoTSDK::clientId[256] = "";
char AliyunIoTSDK::mqttUsername[100] = "";
char AliyunIoTSDK::mqttPwd[256] = "";
char AliyunIoTSDK::domain[150] = "";

char AliyunIoTSDK::ALINK_TOPIC_PROP_POST[150] = "";
char AliyunIoTSDK::ALINK_TOPIC_PROP_SET[150] = "";
char AliyunIoTSDK::ALINK_TOPIC_EVENT[150] = "";
char AliyunIoTSDK::ALINK_TOPIC_USER[150] = "";

static String hmac256(const String &signcontent, const String &secret)
{
    unsigned char hashCode[SHA256HMAC_SIZE];

    const String& key = secret.c_str();
    size_t keySize = secret.length();

#if defined(CONFIG_IDF_TARGET_ESP32S2) || defined(CONFIG_IDF_TARGET_ESP32C3)

    mbedtls_md_context_t sha_ctx;

    mbedtls_md_init(&sha_ctx);

    memset(hashCode, 0x00, sizeof(hashCode));

    int ret = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0) {
        printf("mbedtls_md_setup() returned -0x%04x\n", -ret);
    }

    mbedtls_md_hmac_starts(&sha_ctx, (const unsigned char*)key, keySize);
    mbedtls_md_hmac_update(&sha_ctx, (const unsigned char*)signcontent.c_str(), signcontent.length());
    mbedtls_md_hmac_finish(&sha_ctx, hashCode);

    mbedtls_md_free(&sha_ctx);
#else
    SHA256 sha256;
    sha256.resetHMAC(key.c_str(), keySize);
    sha256.update((const byte *)signcontent.c_str(), signcontent.length());
    sha256.finalizeHMAC(key.c_str(), keySize, hashCode, sizeof(hashCode));
#endif

    // 转为十六进制字符
    String sign = "";
    for (byte i = 0; i < SHA256HMAC_SIZE; ++i)
    {
        sign += "0123456789ABCDEF"[hashCode[i] >> 4];
        sign += "0123456789ABCDEF"[hashCode[i] & 0xf];
    }

    return sign;
}

static void parmPass(JsonVariant parm)
{
    //    const String& method = parm["method"];
    for (int i = 0; i < DATA_CALLBACK_SIZE; i++)
    {
        if (poniter_array[i].key)
        {
            bool hasKey = parm["params"].containsKey(poniter_array[i].key);
            if (hasKey)
            {
                poniter_array[i].fp(parm["params"]);
            }
        }
    }
}
// 所有云服务的回调都会首先进入这里，例如属性下发
static void callback(const String& topic, byte *payload, unsigned int length)
{
    Serial.print("Message arrived [");
    Serial.print(topic);
    Serial.print("] ");
    payload[length] = '\0';
    Serial.println((const String& )payload);

    StaticJsonDocument<200> doc;
    DeserializationError error = deserializeJson(doc, payload); //反序列化JSON数据

    if (topic.indexOf(AliyunIoTSDK::ALINK_TOPIC_PROP_SET) != -1)
    {
        if (!error) //检查反序列化是否成功
        {
            parmPass(doc.as<JsonVariant>()); //将参数传递后打印输出
        }
    } else if(topic.indexOf(AliyunIoTSDK::ALINK_TOPIC_USER) != -1)
    {
        // 自定义订阅回调
        for (int i = 0; i < DATA_CALLBACK_SIZE; i++)
        {
            if(topic == poniter_array[i].key)
                poniter_array[i].fp(doc.as<JsonVariant>());
        }
    }
    else
    {
        for (int i = 0; i < DATA_CALLBACK_SIZE; i++)
        {
            if (topic == poniter_array[i].key)
            {
                poniter_array[i].fp(doc.as<JsonVariant>());
            }
        }
    }
}

static bool mqttConnecting = false;
void(* resetFunc) (void) = 0; //制造重启命令
void AliyunIoTSDK::mqttCheckConnect()
{
    if (client != NULL && !mqttConnecting)
    {
        if (!client->connected())
        {
            client->disconnect();
            Serial.println("Connecting to MQTT Server ...");
            mqttConnecting = true;
            if (client->connect(clientId, mqttUsername, mqttPwd))
            {
                Serial.println("MQTT Connected!");
            }
            else
            {
                Serial.print("MQTT Connect err:");
                Serial.println(client->state());
                retry_count++;
                if(retry_count > RETRY_CRASH_COUNT){
                    resetFunc();
                }
            }
            mqttConnecting = false;
        }
        else
        {
            Serial.println("state is connected");
            retry_count = 0;
        }
    }
}

void AliyunIoTSDK::begin(Client &espClient,
                         const String& _productKey,
                         const String& _deviceName,
                         const String& _deviceSecret,
                         const String& _region)
{
    if (client) {
        delete client;
    }

    client = new PubSubClient(espClient);
    client->setBufferSize(1024);
	client->setKeepAlive(60);
    productKey = _productKey;
    deviceName = _deviceName;
    deviceSecret = _deviceSecret;
    region = _region;
    long times = millis();
    String timestamp = String(times);

    sprintf(clientId, "%s|securemode=3,signmethod=hmacsha256,timestamp=%s|", deviceName.c_str(), timestamp.c_str());

    String signcontent = "clientId";
    signcontent += deviceName;
    signcontent += "deviceName";
    signcontent += deviceName;
    signcontent += "productKey";
    signcontent += productKey;
    signcontent += "timestamp";
    signcontent += timestamp;

    String pwd = hmac256(signcontent, deviceSecret);

    strcpy(mqttPwd, pwd.c_str());

    sprintf(mqttUsername, "%s&%s", deviceName.c_str(), productKey.c_str());
    sprintf(ALINK_TOPIC_PROP_POST, "/sys/%s/%s/thing/event/property/post", productKey.c_str(), deviceName.c_str());
    sprintf(ALINK_TOPIC_PROP_SET, "/sys/%s/%s/thing/service/property/set", productKey.c_str(), deviceName.c_str());
    sprintf(ALINK_TOPIC_EVENT, "/sys/%s/%s/thing/event", productKey.c_str(), deviceName.c_str());
    sprintf(ALINK_TOPIC_USER, "/%s/%s/user", productKey.c_str(), deviceName.c_str());

    sprintf(domain, "%s.iot-as-mqtt.%s.aliyuncs.com", productKey.c_str(), region.c_str());
    client->setServer(domain, MQTT_PORT); /* 连接WiFi之后，连接MQTT服务器 */
    client->setCallback(callback);

    mqttCheckConnect();
}

void AliyunIoTSDK::loop()
{
    client->loop();
    if (millis() - lastMs >= CHECK_INTERVAL)
    {
        lastMs = millis();
        mqttCheckConnect();
        messageBufferCheck();
    }
}

void AliyunIoTSDK::sendEvent(const String& eventId, const String& param)
{
    char topicKey[156];
    sprintf(topicKey, "%s/%s/post", ALINK_TOPIC_EVENT, eventId.c_str());
    char jsonBuf[1024];
    sprintf(jsonBuf, ALINK_EVENT_BODY_FORMAT, param.c_str(), eventId.c_str());
    Serial.println(jsonBuf);
    boolean d = client->publish(topicKey, jsonBuf);
    Serial.print("publish:0 成功:");
    Serial.println(d);
}
void AliyunIoTSDK::sendEvent(const String& eventId)
{
    sendEvent(eventId, "{}");
}
unsigned long lastSendMS = 0;

// 检查是否有数据需要发送
void AliyunIoTSDK::messageBufferCheck()
{
    int bufferSize = 0;
    for (int i = 0; i < MESSAGE_BUFFER_SIZE; i++)
    {
        if (PropertyMessageBuffer[i].key.length() > 0)
        {
            bufferSize++;
        }
    }
    // Serial.println("bufferSize:");
    // Serial.println(bufferSize);
    if (bufferSize > 0)
    {
        if (bufferSize >= MESSAGE_BUFFER_SIZE)
        {
            sendBuffer();
        }
        else
        {
            unsigned long nowMS = millis();
            // 3s 发送一次数据
            if (nowMS - lastSendMS > 5000)
            {
                sendBuffer();
                lastSendMS = nowMS;
            }
        }
    }
}

// 发送 buffer 数据
void AliyunIoTSDK::sendBuffer()
{
    int i;
    String buffer;
    for (i = 0; i < MESSAGE_BUFFER_SIZE; i++)
    {
        if (PropertyMessageBuffer[i].key.length() > 0)
        {
            buffer += "\"" + PropertyMessageBuffer[i].key + "\":" + PropertyMessageBuffer[i].value + ",";
            PropertyMessageBuffer[i].key = "";
            PropertyMessageBuffer[i].value = "";
        }
    }

    buffer = "{" + buffer.substring(0, buffer.length() - 1) + "}";
    send(buffer.c_str());
}

void addMessageToBuffer(const String& key, String value)
{
    int i;
    for (i = 0; i < MESSAGE_BUFFER_SIZE; i++)
    {
        if (PropertyMessageBuffer[i].key.length() == 0)
        {
            PropertyMessageBuffer[i].key = key;
            PropertyMessageBuffer[i].value = value;
            break;
        }
    }
}
void AliyunIoTSDK::send(const String& param)
{
    char jsonBuf[1024];
    sprintf(jsonBuf, ALINK_BODY_FORMAT, param.c_str());
    Serial.println(jsonBuf);
    boolean d = client->publish(ALINK_TOPIC_PROP_POST, jsonBuf);
    Serial.print("publish:0 成功:");
    Serial.println(d);
}
void AliyunIoTSDK::send(const String& key, float number)
{
    addMessageToBuffer(key, String(number));
    messageBufferCheck();
}
void AliyunIoTSDK::send(const String& key, int number)
{
    addMessageToBuffer(key, String(number));
    messageBufferCheck();
}
void AliyunIoTSDK::send(const String& key, double number)
{
    addMessageToBuffer(key, String(number));
    messageBufferCheck();
}

void AliyunIoTSDK::send(const String& key, const String& text)
{
    addMessageToBuffer(key, "\"" + String(text) + "\"");
    messageBufferCheck();
}

int AliyunIoTSDK::bindData(const String& key, poniter_fun fp)
{
    int i;
    for (i = 0; i < DATA_CALLBACK_SIZE; i++)
    {
        if (!poniter_array[i].fp)
        {
            poniter_array[i].key = key;
            poniter_array[i].fp = fp;
            return 0;
        }
    }
    return -1;
}

int AliyunIoTSDK::unbindData(const String& key)
{
    int i;
    for (i = 0; i < DATA_CALLBACK_SIZE; i++)
    {
        if (poniter_array[i].key.equals(key))
        {
            poniter_array[i].key.clear();
            poniter_array[i].fp = NULL;
            return 0;
        }
    }
    return -1;
}


boolean AliyunIoTSDK::publish(const String& topic, const String& payload, bool retained){
    return client->publish(topic.c_str(), payload.c_str(), retained);
}

boolean AliyunIoTSDK::publish(const String& topic, const String& payload){
    return client->publish(topic.c_str(), payload.c_str());
}

boolean AliyunIoTSDK::publishUser(const String& topicSuffix, const String& payload){
    String topic = ALINK_TOPIC_USER;
    return AliyunIoTSDK::publish(topic + topicSuffix, payload);
}

boolean AliyunIoTSDK::subscribeUser(const String& topicSuffix, poniter_fun fp){
    String topic = ALINK_TOPIC_USER;    
    return AliyunIoTSDK::subscribe(topic + topicSuffix, fp);
}

boolean AliyunIoTSDK::unsubscribeUser(const String& topicSuffix){
    String topic = ALINK_TOPIC_USER;
    return AliyunIoTSDK::unsubscribe(topic + topicSuffix);
}

boolean AliyunIoTSDK::subscribe(const String& topic, uint8_t qos, poniter_fun fp){
    boolean ret = false;
    if(client->subscribe(topic.c_str(), qos)){
        ret = true;
        bindData(topic, fp);
        Serial.print("subcribe: ");
        Serial.println(topic);
    }
    return ret;
}

boolean AliyunIoTSDK::subscribe(const String& topic, poniter_fun fp){
    return subscribe(topic, 0, fp);
}

boolean AliyunIoTSDK::unsubscribe(const String& topic){
    boolean ret = false;
    if(client->unsubscribe(topic.c_str())){
        ret = true;
        unbindData(topic);
        Serial.print("unsubcribe: ");
        Serial.println(topic);
    }
    return ret;
}

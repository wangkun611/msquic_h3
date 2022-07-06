#include <stdio.h>
#include <msquic.h>
#include <msquichelper.h>
#include <quic_var_int.h>
#include <lsqpack.h>
#include <lsxpack_header.h>
#include <vector>
#include <algorithm>

using std::vector;

void CxPlatLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
)
{
    _CRT_UNUSED(File);
    _CRT_UNUSED(Line);
    _CRT_UNUSED(Expr);
}

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
const QUIC_API_TABLE* MsQuic;

const QUIC_REGISTRATION_CONFIG RegConfig = { "h3_test", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
HQUIC Registration;

HQUIC Configuration;

QUIC_TLS_SECRETS TlsSecrets;
HQUIC streamControl = NULL;
HQUIC streamDecoder = NULL;
HQUIC streamEncoder = NULL;
HQUIC streamRequest = NULL;
vector<HQUIC>  streamServer;

enum H3FrameType {
    H3FrameData = 0,
    H3FrameHeaders,
    H3FramePriority,
    H3FrameCancelPush,
    H3FrameSettings,
    H3FramePushPromise,
    H3FrameGoaway = 7,
    H3FrameUnknown = 0xFF
};

struct ReceiveBuffer
{
    H3FrameType type = H3FrameUnknown;
    size_t length = 0;
    size_t available = 0;
    uint8_t* data = NULL;
    uint8_t* buffer = NULL;
    size_t   bufferLen = 0;
    ReceiveBuffer() {
        buffer = (uint8_t*)malloc(4096);
        bufferLen = 4096;
    }
};

ReceiveBuffer receiveBuffer;

char DecodeBuffer[1024];
struct lsxpack_header CurDecodeHeader;

void
DecodeUnblocked(void* hblock_ctx)
{ }

struct lsxpack_header* DecodePrepare(void* hblock_ctx,
    struct lsxpack_header* Header,
    size_t Space
)
{
    if (Space > sizeof(DecodeBuffer)) {
        printf("Header too big, %zu\n", Space);
        return NULL;
    }
    if (Header) {
        Header->buf = DecodeBuffer;
        Header->val_len = (lsxpack_strlen_t)Space;
    }
    else {
        Header = &CurDecodeHeader;
        lsxpack_header_prepare_decode(Header, DecodeBuffer, 0, Space);
    }
    return Header;
}

int DecodeProcess(void* hblock_ctx, struct lsxpack_header* Header)
{
    printf("%*.*s: %*.*s\n", Header->name_len, Header->name_len, Header->buf + Header->name_offset,
        Header->val_len, Header->val_len, Header->buf + Header->val_offset);
    return 0;
}

struct lsqpack_dec_hset_if hset_if = {DecodeUnblocked, DecodePrepare, DecodeProcess};

void ReceiveResponseHeader(ReceiveBuffer* buffer)
{
    struct lsqpack_dec Decoder;
    uint8_t* p = NULL;
    lsqpack_dec_init(&Decoder, NULL, 0, 0, &hset_if, (lsqpack_dec_opts)0);
    p = buffer->data;
    lsqpack_dec_header_in(&Decoder, 0, 0, buffer->available, (const unsigned char**) &p, buffer->available, 0, 0);
}

void ReceiveResponseData(ReceiveBuffer* buffer)
{
    printf("[strm] ReceiveResponseData: %d\n", (int)buffer->available);
    printf("%*.*s", (int)buffer->available, (int)buffer->available, buffer->data);
}

// 返回值指示是否完毕
bool ReceiveResponse(QUIC_STREAM_EVENT* Event)
{
    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
        const QUIC_BUFFER* Buffer = &Event->RECEIVE.Buffers[i];

        uint16_t offset = 0;
        do
        {
            if (receiveBuffer.type == H3FrameUnknown) {
                receiveBuffer.type = (H3FrameType)Buffer->Buffer[offset++];
                QUIC_VAR_INT value = 0;
                QuicVarIntDecode(Buffer->Length - offset, Buffer->Buffer, &offset, &value);
                receiveBuffer.length = value;
                receiveBuffer.data = receiveBuffer.buffer;
            }

            size_t copyLength = min(Buffer->Length - offset, receiveBuffer.length - receiveBuffer.available);
            memcpy(receiveBuffer.buffer + receiveBuffer.available, Buffer->Buffer + offset, copyLength);
            offset += copyLength;
            receiveBuffer.available += copyLength;

            if (receiveBuffer.available == receiveBuffer.length) {
                printf("[strm] Receive frame complete: %d\n", receiveBuffer.type);
                if (receiveBuffer.type == H3FrameHeaders) {
                    ReceiveResponseHeader(&receiveBuffer);
                }
                else if (receiveBuffer.type == H3FrameData) {
                    ReceiveResponseData(&receiveBuffer);
                    return true;
                }
                receiveBuffer.type = H3FrameUnknown;
                receiveBuffer.available = receiveBuffer.length = 0;
            }
        } while (offset < Buffer->Length);
    }
    return false;
}

_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API QuicStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
)
{
    switch (Event->Type)
    {
    case QUIC_STREAM_EVENT_RECEIVE:
        printf("[strm][%p] Receive\n", Stream);
        if (Stream == streamRequest) {
            printf("[strm][%p] Request stream receive\n", Stream);
            if (ReceiveResponse(Event)) { // 接收完数据完毕stream
                MsQuic->StreamClose(streamRequest);
                MsQuic->StreamClose(streamControl);
                MsQuic->StreamClose(streamDecoder);
                MsQuic->StreamClose(streamEncoder);
                std::for_each(streamServer.begin(), streamServer.end(), [](HQUIC stream) {
                    MsQuic->StreamClose(stream);
                });
            }
        }
        break;
    default:
        printf("[strm][%p] Recieve event: %d\n", Stream, Event->Type);
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

HQUIC CreateStream(HQUIC Connection, bool BiDir)
{
    HQUIC Stream = NULL;
    QUIC_STATUS Status;

    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, BiDir ? QUIC_STREAM_OPEN_FLAG_NONE : QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
        QuicStreamCallback, NULL, &Stream))) {
        return NULL;
    }

    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        return NULL;
    }
    return Stream;
}

bool StreamSend(HQUIC stream, uint8_t* buffer, size_t bufLen, bool last)
{
    QUIC_STATUS Status;

    // Allocates and builds the buffer to send over the stream.
    //
    QUIC_BUFFER* sendBuffer = (QUIC_BUFFER*)malloc(sizeof(QUIC_BUFFER) + bufLen);
    if (sendBuffer == NULL) {
        return false;
    }
    sendBuffer->Length = (uint32_t)bufLen;
    sendBuffer->Buffer = (uint8_t*)sendBuffer + sizeof(QUIC_BUFFER);
    memcpy(sendBuffer->Buffer, buffer, bufLen);

    if (QUIC_FAILED(Status = MsQuic->StreamSend(stream, sendBuffer, 1, last ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, (void* )sendBuffer))) {
        free(sendBuffer);
        return false;
    }

    return true;
}

typedef struct HEADER {
    const char* Name;
    const char* Value;
} HEADER;

HEADER Headers[] = {
    { ":method", "GET" },
    { ":path", "/static/css/style.css" },
    { ":scheme", "https" },
    { ":authority", "quic.nginx.org" },
    { "user-agent", "curl/7.82.0-DEV" },
    { "accept", "*/*" },
};

bool HttpSendRequest(_In_ HQUIC hRequest, _In_ HQUIC hEncoder)
{
    struct lsqpack_enc Encoder;
    uint8_t tsu_buf[LSQPACK_LONGEST_SDTC];
    size_t tsu_buf_sz = sizeof(tsu_buf);
    uint8_t encBuffer[4096] = { 0 };
    uint8_t headerBuffer[4096] = { 0 };
    uint8_t prefixBuffer[32] = { 0 };
    size_t headerSize = 0;
    size_t encSize = 0;
    size_t prefixSize = 0;

    lsqpack_enc_preinit(&Encoder, NULL);
    if (lsqpack_enc_init(&Encoder, NULL, 4096, 4096, 0, LSQPACK_ENC_OPT_STAGE_2, tsu_buf, &tsu_buf_sz) != 0) {
        printf("lsqpack_enc_init failed\n");
        return false;
    }
    if (lsqpack_enc_start_header(&Encoder, 0, 0) != 0) {
        printf("lsqpack_enc_start_header failed\n");
        return false;
    }
    size_t enc_off = 0, hea_off = 0;
    for (size_t i = 0; i < _countof(Headers); ++i) {
        lsxpack_header_t header = { 0 };
        char Buffer[512] = { 0 };
        header.buf = Buffer;
        header.name_offset = 0;
        header.name_len = strlen(Headers[i].Name);
        header.val_offset = strlen(Headers[i].Name);
        header.val_len = strlen(Headers[i].Value);
        memcpy(Buffer, Headers[i].Name, header.name_len);
        memcpy(Buffer + header.name_len, Headers[i].Value, header.val_len);

        size_t enc_size = sizeof(encBuffer) - enc_off;
        size_t header_size = sizeof(headerBuffer) - hea_off;
        lsqpack_enc_encode(&Encoder, encBuffer + enc_off, &enc_size, headerBuffer + hea_off, &header_size,
            &header, (lsqpack_enc_flags)0);
        enc_off += enc_size;
        hea_off += header_size;
    }

    headerSize = hea_off;
    encSize = enc_off;
    enum lsqpack_enc_header_flags hflags;
    auto pref_sz = lsqpack_enc_end_header(&Encoder, prefixBuffer, sizeof(prefixBuffer), &hflags);
    if (pref_sz < 0) {
        printf("lsqpack_enc_end_header failed\n");
        return false;
    }
    prefixSize = pref_sz;

    lsqpack_enc_cleanup(&Encoder);

    if (encSize) {
        StreamSend(hEncoder, encBuffer, encSize, false);
    }

    uint8_t Buffer[200];
    Buffer[0] = 0x01;
    uint8_t* BufferEnd = QuicVarIntEncode(prefixSize + headerSize, Buffer + 1);
    StreamSend(hRequest, Buffer, BufferEnd - Buffer, false);
    StreamSend(hRequest, prefixBuffer, prefixSize, false);
    StreamSend(hRequest, headerBuffer, headerSize, true);

    return true;
}

void HttpSend(_In_ HQUIC Connection)
{
    uint8_t data[100];

    streamControl = CreateStream(Connection, false);
    streamEncoder = CreateStream(Connection, false);
    streamDecoder = CreateStream(Connection, false);
    streamRequest = CreateStream(Connection, true);
    data[0] = 0;
    StreamSend(streamControl, data, 1, false);
    memcpy(data, "\x02\x3f\xe1\x1f", 4); // 设置DYN Table大小4096
    StreamSend(streamEncoder, data, 4, false);
    data[0] = 3;
    StreamSend(streamDecoder, data, 1, false);

    HttpSendRequest(streamRequest, streamEncoder);
}

_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
)
{
    switch (Event->Type)
    {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        WriteSslKeyLogFile("d:\\quic.log", TlsSecrets);
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        HttpSend(Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        }
        else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn][%p] All done\n", Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        printf("[conn][%p] Peer Stram Started [%p]\n", Connection, Event->PEER_STREAM_STARTED.Stream);
        if (Event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) {
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, QuicStreamCallback, NULL);
            streamServer.push_back(Event->PEER_STREAM_STARTED.Stream);
        }
        else {
            MsQuic->StreamClose(Event->PEER_STREAM_STARTED.Stream);
        }

        break;
    default:
        printf("[conn][%p] Recieve event: %d\n", Connection, Event->Type);
        break;

    }
    return QUIC_STATUS_SUCCESS;
}

int main(int argc, char** argv)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        return Status;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    const QUIC_BUFFER Alpn = { sizeof("h3") - 1, (uint8_t*)"h3" };

    QUIC_SETTINGS Settings = { 0 };
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = 1000;                        
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.PeerBidiStreamCount = 1000;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.PeerUnidiStreamCount = 3;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;   // 客户端关闭证书校验

    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        goto Error;
    }

    HQUIC Connection = NULL;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    Status =MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS, sizeof(TlsSecrets), &TlsSecrets);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, "quic.nginx.org", 443))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

Error:
    if (QUIC_FAILED(Status) && Connection != NULL) {
        MsQuic->ConnectionClose(Connection);
    }

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return 0;
}

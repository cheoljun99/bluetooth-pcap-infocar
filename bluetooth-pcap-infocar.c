#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h> // For ntohs, htons
#include <unistd.h>
#include <ctype.h> // for isprint

// L2CAP 헤더 구조 (Length + CID)
typedef struct {
    uint16_t length;   // Length of payload
    uint16_t cid;      // Channel ID
    uint8_t payload[]; // Variable length payload
} l2cap_packet_t;

// ASCII 값을 16진수 숫자로 변환하는 함수
uint8_t ascii_to_hex(uint8_t ascii) {
    if (ascii >= '0' && ascii <= '9') {
        return ascii - '0'; // 숫자 '0' ~ '9' 처리
    } else if (ascii >= 'A' && ascii <= 'F') {
        return ascii - 'A' + 10; // 문자 'A' ~ 'F' 처리
    } else if (ascii >= 'a' && ascii <= 'f') {
        return ascii - 'a' + 10; // 소문자 'a' ~ 'f' 처리 (옵션)
    } else {
        printf("Error: Invalid ASCII character for hex conversion: 0x%02X\n", ascii);
        return 0; // 잘못된 경우 기본값 반환
    }
}



// CAN 데이터 처리 함수
void process_obd2_data(const uint8_t *data, uint32_t length) {

    const uint8_t *payload = data + 4;
    // 7E8 확인
    if (payload[0] == '7' && payload[1] == 'E' && payload[2] == '8') {
        uint8_t byte_count = (payload[3] - '0') * 10 + (payload[4] - '0');
        if (byte_count < 2 || 5 + byte_count > length) {
            printf("OBD-II: Invalid byte count or out-of-bounds data\n");
            return;
        }
        
        
	// 디버깅 및 변환 코드 수정
	uint8_t service_id = ascii_to_hex(payload[5]) * 16 + ascii_to_hex(payload[6]);
	uint8_t pid = ascii_to_hex(payload[7]) * 16 + ascii_to_hex(payload[8]);


        if (service_id == 0x41 || pid == 0x0C) {
        //RPM 계산
        uint8_t rpm_high = ascii_to_hex(payload[9]) * 16 + ascii_to_hex(payload[10]);
        uint8_t rpm_low = ascii_to_hex(payload[11]) * 16 + ascii_to_hex(payload[12]);
	uint16_t raw_rpm = (rpm_high << 8) | rpm_low;
	float rpm = raw_rpm / 4.0;

	printf("HCI_ACL Packet Detected (L2CAP)\n");
	printf("CAN ID: 7E8\n");
	printf("Valid Byte Count: %d\n", byte_count);
	printf("Requested Data: Service ID: 0x%02X, PID: 0x%02X (RPM)\n", service_id, pid);
	printf("Actual RPM: %.2f (0x%02X 0x%02X)\n", rpm, rpm_high, rpm_low);
	printf("\n");
        }
        
        if (service_id == 0x41 || pid == 0x0D) {
        //속도 계산
        uint8_t speed = ascii_to_hex(payload[9]) * 16 + ascii_to_hex(payload[10]);


	printf("HCI_ACL Packet Detected (L2CAP)\n");
	printf("CAN ID: 7E8\n");
	printf("Valid Byte Count: %d\n", byte_count);
	printf("Requested Data: Service ID: 0x%02X, PID: 0x%02X (SPEED)\n", service_id, pid);
	printf("Actual speed: %d (0x%02X)\n", speed, speed);
	printf("\n");
        }
        

        return;
    }
}

// L2CAP 데이터 처리 함수 (OBD-II 프로토콜 처리)
void process_l2cap(const uint8_t *data, uint32_t length) {
    if (length < 4) { // 최소 L2CAP 헤더 크기
        printf("L2CAP: Insufficient length\n");
        return;
    }

    l2cap_packet_t *l2cap = (l2cap_packet_t *)data;
    uint16_t cid = ntohs(l2cap->cid); // L2CAP Channel ID

    // L2CAP 페이로드 추출
    const uint8_t *payload = l2cap->payload;
    uint32_t payload_length = length - 4; // L2CAP 헤더 크기(4바이트) 제외

    // OBD-II 데이터 처리
    process_obd2_data(payload, payload_length);
}

// HCI 패킷 타입 검사 및 처리
void process_packet(const uint8_t *data, uint32_t length) {
    if (length < 5) { // 최소 패킷 길이 확인
        printf("Packet too short to determine type\n");
        return;
    }

    // 데이터 오프셋 조정 (앞의 4바이트 스킵)
    const uint8_t *adjusted_data = data + 4;
    uint8_t packet_type = adjusted_data[0];

    if (packet_type == 0x02) { // HCI_ACL 데이터만 처리
        // HCI_ACL 헤더 (4 bytes) 제거 후 L2CAP 데이터 처리
        const uint8_t *l2cap_data = adjusted_data + 4; // HCI_ACL 헤더 크기(4바이트 제거)
        uint32_t l2cap_length = length - 8; // 앞의 4바이트와 HCI_ACL 헤더(4바이트) 제거

        if (l2cap_length >= 4) { // L2CAP 최소 길이 확인
            process_l2cap(l2cap_data, l2cap_length);
        } else {
            printf("HCI_ACL Packet Detected but insufficient L2CAP data length.\n");
        }
    }
}

// main 함수
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <fifo pcap file>\n", argv[0]);
        return -1;
    }

    const char *fifo_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap 파일 열기
    pcap_t *handle = pcap_open_offline(fifo_file, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return -1;
    }

    struct pcap_pkthdr *header;
    const uint8_t *data;

    printf("Listening for new packets in: %s\n", fifo_file);

    // 실시간 파일 읽기 루프
    while (1) {
        int ret = pcap_next_ex(handle, &header, &data);
        if (ret == 1) { // 패킷 성공적으로 읽음
            process_packet(data, header->caplen);
        } else if (ret == PCAP_ERROR_BREAK || ret == 0) { // EOF 또는 타임아웃
            break;
        } else if (ret == PCAP_ERROR) { // 에러 발생
            fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
    return 0;
}


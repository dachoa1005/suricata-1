#ifndef __DECODE_ARP_H__
#define __DECODE_ARP_H__

#define ARP_HEADER_LEN 28 /**< Header length */

typedef struct _ARPHdr {
    uint16_t arp_hw_type;    /**< Hardware type */
    uint16_t arp_proto_type; /**< Protocol type*/
    uint8_t arp_hw_size;     /**< Hardware size */
    uint8_t arp_proto_size;  /**< Protocol size */
    uint16_t arp_opcode;     /**< ARP opcode*/
    uint8_t arp_src_mac[6];  /**< Sender MAC address */
    uint8_t arp_src_ip[4];     /**< Sender IP address */
    uint8_t arp_des_mac[6];  /**< Destination MAC address */
    uint8_t arp_des_ip[4];     /**< Destination IP address */
} ARPHdr;


// int DecodeARP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t );

#endif /* __DECODE_ARP_H__ */
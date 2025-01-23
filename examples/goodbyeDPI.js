var wd = require("../windivert.js");
class Filter {
    static #instance;
    #ipIdTemplate
    #maxPayloadSizeTemplate
    #noLocalIPv4Dst
    #noLocalIPv4Src
    #noLocalIPv6Dst
    #noLocalIPv6Src
    #filterStringTemplate
    #passiveFilterStringTemplate
    constructor(parameters) {
        if (Filter.#instance) {
            throw new Error("Singleton instance already exists. Please use getInstance().");
        }

        this.#ipIdTemplate = `#IPID#`;

        this.#maxPayloadSizeTemplate = `#MAXPAYLOADSIZE#`;

        this.#noLocalIPv4Dst = `((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and (ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))`;

        this.#noLocalIPv4Src = `((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and (ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and (ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and (ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and (ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))`;

        this.#noLocalIPv6Dst = `((ipv6.DstAddr > ::1) and (ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and (ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and (ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and (ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0))`;

        this.#noLocalIPv6Src = `((ipv6.SrcAddr > ::1) and (ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and (ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and (ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and (ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0))`;

        this.#filterStringTemplate = `(tcp and !impostor and !loopback ${this.#maxPayloadSizeTemplate} and (((inbound and (((ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) ${this.#ipIdTemplate}) and tcp.SrcPort == 80 and tcp.Ack) or ((tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn))) and (${this.#noLocalIPv4Src} or ${this.#noLocalIPv6Src})) or (outbound and (tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack and (${this.#noLocalIPv4Dst} or ${this.#noLocalIPv6Dst}))))`;

        this.#passiveFilterStringTemplate = `inbound and ip and tcp and !impostor and !loopback and (true ${this.#ipIdTemplate}) and (tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and ${this.#noLocalIPv4Src}`;

        this.quicBlockPassiveFilter = `outbound and !impostor and !loopback and udp and udp.DstPort == 443 and udp.PayloadLength >= 1200 and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01`;

        Filter.#instance = this;
    }
    static getInstance() {
        if (!Filter.#instance) {
            Filter.#instance = new Filter();
        }
        return Filter.#instance;
    }
    generateFilters(ipID, maxPayloadSize = 1200) {
        this.filter = this.#filterStringTemplate;
        this.passiveFilter = this.#passiveFilterStringTemplate;
        if (ipID && typeof ipID === 'number' && ipID >= 0 && ipID <= 65535) {
            this.ipID = ipID;
            this.#addIpIdStr(ipID);
        } else if (ipID !== undefined && ipID !== null) {
            console.warn("Invalid ipID provided.  Must be a number between 0 and 65535. Ignoring.");
        }
        if (maxPayloadSize && typeof maxPayloadSize === 'number' && maxPayloadSize >= 0) {
            this.maxPayloadSize = maxPayloadSize;
            this.#addMaxPayloadSizeStr(maxPayloadSize);
        } else if (maxPayloadSize !== undefined && maxPayloadSize !== null) {
            console.warn("Invalid maxPayloadSize provided.  Must be a number greater than or equal to 0. Ignoring.");
        }
        this.#finalizeFilterStrings();
    }

    addFilterStr(proto, port) {
        const udp = ` or(udp and !impostor and!loopback and (udp.SrcPort == ${port} or udp.DstPort == ${port}))`;
        const tcp = ` or(tcp and !impostor and !loopback ${this.#maxPayloadSizeTemplate} and (tcp.SrcPort == ${port} or tcp.DstPort == ${port}))`;
        if (proto === 'IPPROTO_UDP') {
            this.filter += udp;
        } else {
            this.filter += tcp;
        }
        if (this.maxPayloadSize !== undefined && this.maxPayloadSize !== null) {
            this.#addMaxPayloadSizeStr(this.maxPayloadSize);
        }
        this.#finalizeFilterStrings();
    }
    #addIpIdStr(id) {
        const ipId = " or ip.Id == " + id;
        this.filter = this.filter.replace(this.#ipIdTemplate, ipId);
        this.passiveFilter = this.passiveFilter.replace(this.#ipIdTemplate, ipId);
    }
    #addMaxPayloadSizeStr(maxPayload) {
        const maxPayloadSizeStr = `and (tcp.PayloadLength ? tcp.PayloadLength < ${maxPayload} or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 or (tcp.Payload[0] == 0x16 && tcp.Payload[1] == 0x03 && tcp.Payload[2] <= 0x03): true)`;

        this.filter = filterString.replace(this.#maxPayloadSizeTemplate, maxPayloadSizeStr);
    }
    #finalizeFilterStrings() {
        this.filter = this.filter.replace(this.#ipIdTemplate, "");
        this.filter = this.filter.replace(this.#maxPayloadSizeTemplate, "");

        this.passiveFilter = this.passiveFilter.replace(this.#ipIdTemplate, "");
        this.passiveFilter = this.passiveFilter.replace(this.#maxPayloadSizeTemplate, "");
    }
}
class Patcher {
    #patched;
    #headerReader;
    constructor() {
        this.#patched = false;
        this.#headerReader = new wd.HeaderReader();
        this.packetInfo = null;
        this.addrInfo = null;
    }
    setPacketBuffer(buffer) {
        this.#headerReader.setPacketBuffer(buffer);
        this.packetInfo = this.#headerReader.WinDivertHelperParsePacket();
        this.#patched = false;
    }
    setAdressBuffer(buffer) {
        this.#headerReader.setAddressBuffer(buffer);
        this.addrInfo = this.#headerReader.readAddressData();
    }
    changeWindowSize(tcpHeader, windowSize) {
        if (windowSize >= 1 && windowSize <= 65535) {
            tcpHeader.setWindow(windowSize);
            this.#patched = true;
        }
    }
    sendFakePacket(winDivert) {

    }
    createFragmentPacket(winDivert, https_fragment_size = 2) {
        try {
            if (!winDivert) {
                throw new Error('winDivert parameter is required');
                
            }
            if (typeof https_fragment_size !== 'number' || https_fragment_size < 1) {
                throw new Error('https_fragment_size must be a valid positive number');
            }
            
            if (!this.#headerReader || !this.packetInfo) {
                throw new Error('HeaderReader or packetInfo is not initialized');
            }

            let current_fragment_size;

            if (this.packetInfo.isTLSHandshake) {

                if (this.packetInfo.ServerNameOffset && this.packetInfo.ServerNameLength) {                    
                    current_fragment_size = this.packetInfo.ServerNameOffset - this.packetInfo.PayloadOffset;
                } else {
                    current_fragment_size = https_fragment_size;
                }
            } else {
                current_fragment_size = https_fragment_size;
            }
            
            if (!this.#headerReader.packetLength || !this.packetInfo.PayloadLength) {
                throw new Error('Packet length information is missing');
            }

            const packetLength = this.#headerReader.packetLength;
            const sequenceNumber = this.packetInfo.ProtocolHeader.getSeqNum();
            const firstSegmentSize = packetLength - this.packetInfo.PayloadLength + https_fragment_size;
            const secondSegmentSize = packetLength - https_fragment_size;
            this.packetInfo.IpHeader.setLength(firstSegmentSize);
            const firstBuffer = new Uint8Array(firstSegmentSize);
            firstBuffer.set(this.#headerReader.packetBuffer.slice(0, firstSegmentSize));

            const secondBuffer = new Uint8Array(secondSegmentSize);
            this.packetInfo.IpHeader.setLength(secondSegmentSize);
            this.packetInfo.ProtocolHeader.setSeqNum(sequenceNumber + https_fragment_size);
            secondBuffer.set(this.#headerReader.packetBuffer.slice(0, firstSegmentSize - https_fragment_size), 0);
            secondBuffer.set(this.#headerReader.packetBuffer.slice(firstSegmentSize, packetLength), firstSegmentSize - https_fragment_size);

            this.packetInfo.ProtocolHeader.setSeqNum(sequenceNumber);
            this.packetInfo.IpHeader.setLength(packetLength);

            this.addrInfo.setIPChecksum(0);
            this.addrInfo.setTCPChecksum(0);
            let helper = winDivert.HelperCalcChecksums({ packet: secondBuffer }, 0);
            if (helper.IPChecksum === 0 || helper.TCPChecksum === 0) {
                console.log("checksum error");
                return;
            }

            this.addrInfo.setIPChecksum(helper.IPChecksum);
            this.addrInfo.setTCPChecksum(helper.TCPChecksum);
            winDivert.send({ packet: secondBuffer, addr: this.#headerReader.addressBuffer });

            this.addrInfo.setIPChecksum(0);
            this.addrInfo.setTCPChecksum(0);
            helper = winDivert.HelperCalcChecksums({ packet: firstBuffer }, 0);
            if (helper.IPChecksum === 0 || helper.TCPChecksum === 0) {
                console.log("checksum error");
                return;
            }
            this.addrInfo.setIPChecksum(helper.IPChecksum);
            this.addrInfo.setTCPChecksum(helper.TCPChecksum);
            winDivert.send({ packet: firstBuffer, addr: this.#headerReader.addressBuffer });
            return false;

        } catch (error) {
            console.error('createFragmentPacket error:', error.message);
            throw error; 
        }
    }

}
(async () => {
    const filter = Filter.getInstance();
    filter.generateFilters(null, null);
    let passiveWindivert = await wd.createWindivert(filter.passiveFilter, wd.LAYERS.NETWORK, wd.FLAGS.DROP);
    passiveWindivert.open();
    let quicWindivert = await wd.createWindivert(filter.quicBlockPassiveFilter, wd.LAYERS.NETWORK, wd.FLAGS.DROP);
    quicWindivert.open();
    let activeWindivert = await wd.createWindivert(filter.filter, wd.LAYERS.NETWORK, wd.FLAGS.DEFAULT);
    activeWindivert.open();
    const patcher = new Patcher();
    wd.addReceiveListener(activeWindivert, (packet, addr) => {
        patcher.setAdressBuffer(addr);
        patcher.setPacketBuffer(packet);
        if (patcher.packetInfo.Protocol === wd.PROTOCOLS.TCP && patcher.packetInfo.FragOff === 0) {
            if (patcher.addrInfo.getOutbound() &&
                (patcher.packetInfo.PayloadLength === 2 ||
                    patcher.packetInfo.PayloadLength > 16) &&
                patcher.packetInfo.ProtocolHeader.getDstPort() !== 80 &&
                patcher.packetInfo.isTLSHandshake
            ) {

                return patcher.createFragmentPacket(activeWindivert, 2);
            }
        }

    });
    setTimeout(() => {
        try {
            activeWindivert.close();
            quicWindivert.close();
            passiveWindivert.close();
        } catch (error) {
            console.error("Error:", error);
        }
    }, 600000);
})();
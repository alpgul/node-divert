const wd = require('bindings')('WinDivert');
const { HeaderReader, BYTESWAP16 } = require('./decoders.js');

const FLAGS = Object.freeze({
	DEFAULT: 0x0000,
	SNIFF: 0x0001,
	DROP: 0x0002,
	RECV_ONLY: 0x0004,
	READ_ONLY: 0x0004,  // Same as RECV_ONLY
	SEND_ONLY: 0x0008,
	WRITE_ONLY: 0x0008, // Same as SEND_ONLY
	NO_INSTALL: 0x0010,
	FRAGMENTS: 0x0020
});
const PROTOCOLS = Object.freeze({
	TCP: 6,
	UDP: 17,
	ICMP: 1,
	ICMPV6: 58,

});
const LAYERS = Object.freeze({
	NETWORK: 0,
	NETWORK_FORWARD: 1,
	FLOW: 2,
	SOCKET: 3,
	REFLECT: 4
});
async function checkAdmin() {
	await import('is-admin').then(async (isAdmin) => {
		if (!await isAdmin.default()) {
			throw new Error('You must run this application as an administrator.');
		}
	});
}
function createWindivert(filter, layer, flag) {
	return new wd.WinDivert(filter, layer, flag);
};

function addReceiveListener(handle, callback) {
	try {
		handle.recv(function (packet, addr) {
			const newPacket = callback(packet, addr);
			if (Buffer.isBuffer(newPacket)) {
				try {
					handle.HelperCalcChecksums(newPacket, 0);
					handle.send({ packet: newPacket, addr })
				} catch (error) {
					console.error("Recv Error:", error);
				}
			} else if (newPacket === undefined) {
				handle.send({ packet, addr });
			}
		});
	} catch (error) {
		console.error(error);
	}
};

module.exports = {
	FLAGS,
	LAYERS,
	PROTOCOLS,
	createWindivert,
	addReceiveListener,
	HeaderReader,
	BYTESWAP16
};

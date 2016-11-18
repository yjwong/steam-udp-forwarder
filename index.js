'use strict';
const fs = require('fs');
const os = require('os');
const net = require('net');

const Promise = require('bluebird');
const inquirer = require('inquirer');

const Cap = require('cap').Cap;
const decoders = require('cap').decoders;
const PROTOCOL = decoders.PROTOCOL;

// Obtain program parameters.
const GetProgramParams = Promise.coroutine(function* () {
  return yield inquirer.prompt([{
    type: 'list',
    name: 'interface',
    message: 'Which network interface would you like to listen on?',
    choices: () => {
      const interfaces = os.networkInterfaces();
      return Object.keys(interfaces).reduce((choices, name) => {
        interfaces[name]
          .filter(item => item.family === 'IPv4' && item.internal === false)
          .map(item => ({
            value: item,
            name: `${name} (${item.address})`,
            short: item.address
          }))
          .forEach(choice => choices.push(choice));
        return choices;
      }, []);
    }
  }, {
    type: 'input',
    name: 'peerAddress',
    message: 'What is the peer\'s address?',
    validate: input => net.isIPv4(input)
  }]);
});

const IPToBuffer = function (IP) {
  const buffer = Buffer.alloc(4);
  IP.split('.').forEach((octet, index) => buffer[index] = parseInt(octet));
  return buffer;
};

const MACToBuffer = function (MAC) {
  return Buffer.alloc(6, MAC.replace(/(:|-)/g, ''), 'hex');
}

const GetGatewayIP = Promise.coroutine(function* () {
  const network = Promise.promisifyAll(require('network'));
  return yield network.get_gateway_ipAsync(); 
});

const GetGatewayMAC = Promise.coroutine(function* (iface, sourceMAC, targetIP) {
  const capture = new Cap();
  const device = Cap.findDevice(iface);
  const filter = 'arp';
  const bufSize = 10 * 1024 * 1024;
  const buffer = new Buffer(65535);
  const linkType = capture.open(device, filter, bufSize, buffer);

  let newBuffer = Buffer.from([
    // ETHERNET
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0: Destination MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6: Source MAC
    0x08, 0x06,                         // 12: EtherType = ARP
    // ARP
    0x00, 0x01,                         // 14: Hardware type: Ethernet
    0x08, 0x00,                         // 16: Protocol: IPv4
    0x06, 0x04,                         // 18: Hardware address length, protocol address length
    0x00, 0x01,                         // 20: Operation: ARP, who-has
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 22: Sender MAC
    0x00, 0x00, 0x00, 0x00,             // 28: Sender address
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 32: Target MAC
    0x00, 0x00, 0x00, 0x00              // 38: Target address
  ]);

  // Copy source MAC into buffer.
  MACToBuffer(sourceMAC).copy(newBuffer, 6);
  MACToBuffer(sourceMAC).copy(newBuffer, 22);

  // Copy source IP info buffer.
  IPToBuffer(iface).copy(newBuffer, 28);
  
  // Copy target IP into buffer.
  IPToBuffer(targetIP).copy(newBuffer, 38);

  // Send the packet out and wait for a response.
  const waitForARP = new Promise((resolve, reject) => {
    capture.on('packet', (nbytes, trunc) => {
      if (linkType !== 'ETHERNET') { return; }
      let ret = decoders.Ethernet(buffer);

      if (ret.info.type !== PROTOCOL.ETHERNET.ARP) { return; }
      ret = decoders.ARP(buffer, ret.offset);

      if (MACToBuffer(ret.info.targetmac).equals(MACToBuffer(sourceMAC)) &&
          IPToBuffer(ret.info.senderip).equals(IPToBuffer(targetIP)) &&
          IPToBuffer(ret.info.targetip).equals(IPToBuffer(iface))) {
        resolve(ret.info.sendermac);
      }
    });
  });
  
  capture.send(newBuffer, newBuffer.length);
  return yield waitForARP;
});

Promise.coroutine(function* () {
  const params = yield GetProgramParams();
  const gatewayIP = yield GetGatewayIP();
  const gatewayMAC = yield GetGatewayMAC(params.interface.address, params.interface.mac, gatewayIP);
  console.log(`Resolved gateway: ${gatewayIP} (${gatewayMAC})`);

  const c = new Cap();
  const device = Cap.findDevice(params.interface.address);
  const filter = 'udp and dst port 27036';
  const bufSize = 10 * 1024 * 1024;
  const buffer = new Buffer(65535);
  const linkType = c.open(device, filter, bufSize, buffer);
  c.setMinBytes && c.setMinBytes(0);
  console.log('Network interface opened successfully, waiting for Steam packets');

  c.on('packet', (nbytes, trunc) => {
    //console.log(`packet: length ${nbytes} bytes, truncated? ${trunc ? 'yes' : 'no'}`);
    if (linkType !== 'ETHERNET') { return; }
    let ret = decoders.Ethernet(buffer);

    if (ret.info.type !== PROTOCOL.ETHERNET.IPV4) { return; }
    ret = decoders.IPV4(buffer, ret.offset);
    if (ret.info.dstaddr !== "255.255.255.255") { return; }
    console.log(`Received packet from ${ret.info.srcaddr}`);

    if (ret.info.protocol !== PROTOCOL.IP.UDP) { return; }
    ret = decoders.UDP(buffer, ret.offset);

    // Send to peer.
    let newBuffer = Buffer.from([
      // ETHERNET
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0: Destination MAC = <placeholder>
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6: Source MAC = <placeholder>
      0x08, 0x00,                         // 12: EtherType = IP
      // IP
      0x45,                               // 14: IPv4, 20 byte header
      0x00,                               // 15: Differentiated services field + ECN
      0x00, 0x45,                         // 16: Total length: 69 bytes
      0x7a, 0xb0,                         // 18: Identification
      0x00, 0x00,                         // 20: Flags + fragmentation offset
      0x80,                               // 22: TTL: 128
      0x11,                               // 23: Protocol = UDP
      0x00, 0x00,                         // 24: Checksum
      0x00, 0x00, 0x00, 0x00,             // 26: Source = <placeholder>
      0x00, 0x00, 0x00, 0x00,             // 30: Destination = <placeholder>
      // UDP
      0x69, 0x9c,                         // 34: Source port = 27036
      0x69, 0x9c,                         // 36: Destination port = 27036
      0x00, 0x31,                         // 38: Length: 49
      0x00, 0x00                          // 40: Checksum
    ]);

    // Write the destination and source MAC.
    MACToBuffer(gatewayMAC).copy(newBuffer, 0);
    MACToBuffer(params.interface.mac).copy(newBuffer, 6);

    // Write the source and destination.
    IPToBuffer(params.interface.address).copy(newBuffer, 26);
    IPToBuffer(params.peerAddress).copy(newBuffer, 30);

    // Write the UDP header length.
    newBuffer.writeInt16BE(ret.info.length + 8, 38);

    // Write the IP header length.
    newBuffer.writeInt16BE(ret.info.length + 8 + 20, 16);

    // Compute checksum for IP header.
    let checksum = 0;
    for (let i = 0; i < 10; i++) {
      checksum += newBuffer.readUInt16BE(14 + i * 2);
    }
    let carry = (checksum & 0xf0000) >>> 16;
    checksum += carry;
    checksum = ~checksum;
    checksum &= 0xffff;

    // Write the checksum.
    newBuffer.writeUInt16BE(checksum, 24);

    // Write the UDP packet.
    console.log(`Forwarding packet to peer ${params.peerAddress}`);
    newBuffer = Buffer.concat([ newBuffer, buffer.slice(ret.offset, ret.offset + ret.info.length) ]);
    c.send(newBuffer, newBuffer.length);
  });
})();

# Steam In-Home Streaming UDP Forwarder

Steam's [In-Home Streaming](http://store.steampowered.com/streaming/) feature only
works between hosts on the same subnet at the moment. This project allows you to
cross subnet boundaries by forwarding Steam's discovery UDP packets across the
network.

## Requirements

- [WinPcap](https://www.winpcap.org/) 
- Windows only at the moment
- Steam clients on both hosts
- Microsoft Visual Studio with an appropriate compiler toolchain

## How to Use

The easiest way to get started is to use the `bootstrap.bat` script. This will
install Node.js and `npm` locally. 

Once you have Node.js and `npm`, simply do `npm install` then `node index.js`.

A series of questions will be asked about your hosts.

## Credits

- [Coding Range](https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol) for analysis of the protocol
- [SteamKit](https://github.com/SteamRE/SteamKit) for the Protocol Buffers

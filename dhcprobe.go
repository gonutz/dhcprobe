package dhcprobe

import (
	"errors"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/raw"
)

// DetectDHCPsByName is a shortcut to use net.InterfaceByName to get the
// interface and call DetectDHCPs with it.
func DetectDHCPsByName(interfaceName string, timeout time.Duration) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return 0, errors.New("dhcprobe.DetectDHCPsByName: cannot find the " +
			"interface with the given name: " + err.Error())
	}
	return DetectDHCPs(iface, timeout)
}

// DetectDHCPs probes the given interface for DHCP servers and returns the
// number of DHCP servers that answered. This function will timeout after the
// given duration. This timeout is for the whole function, independent of how
// many servers answer.
func DetectDHCPs(iface *net.Interface, timeout time.Duration) (int, error) {
	now := time.Now()
	deadline := now.Add(timeout)

	wrap := func(msg string, err error) (int, error) {
		return 0, errors.New("dhcprobe.DetectDHCPs: " + msg + ": " + err.Error())
	}

	conn, err := raw.ListenPacket(iface, uint16(layers.EthernetTypeIPv4), nil)
	if err != nil {
		return wrap("cannot open a connection on the given interface", err)
	}
	defer conn.Close()

	err = conn.SetReadDeadline(deadline)
	if err != nil {
		return wrap("cannot set deadline on the connection", err)
	}

	rand.Seed(now.UnixNano())
	transactionID := rand.Uint32()

	packet := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: iface.HardwareAddr,
		Xid:          transactionID,
		Options: []layers.DHCPOption{
			{
				Type:   layers.DHCPOptMessageType,
				Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
				Length: 1,
			},
		},
	}
	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       layers.EthernetBroadcast,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{0, 0, 0, 0},
		DstIP:    []byte{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
	}
	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	udp.SetNetworkLayerForChecksum(&ip)
	err = gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, packet)
	if err != nil {
		return wrap("failed to serialize DHCP message", err)
	}

	_, err = conn.WriteTo(buf.Bytes(), &raw.Addr{HardwareAddr: eth.DstMAC})
	if err != nil {
		return wrap("failed to send DHCP broadcast", err)
	}

	dhcpServerCount := 0
	recvBuf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(recvBuf)

		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return wrap("failed to read DHCP response", err)
		}

		packet := parsePacket(recvBuf[:n])
		if packet == nil {
			continue
		}

		if packet.Xid == transactionID && packet.Operation == layers.DHCPOpReply {
			if isOffer(packet) {
				// TODO What if a server answers twice? Create a set with an ID
				// made up of IP and MAC address to identify a server.
				dhcpServerCount++
			}
		}
	}

	// TODO Are we done here? Right now we have a number of offers and
	// potentially the DHCP servers are reserving an IP for us for a while. We
	// should really tell them that we are never going to use the IP. But there
	// seems to be no way to do that.
	//
	// Sending a DHCPDECLINE message would indicate that the server has
	// overlooked a network configuration problem and do who knows what.
	//
	// Sending a DHCPREQUEST with a fake DHCP may also cause trouble. Other
	// DHCPs might consider the IP taken which again is not right.
	//
	// Not doing anything and waiting for the DHCP server to realize we are not
	// going to come back might be our best options here.

	return dhcpServerCount, nil
}

func parsePacket(data []byte) *layers.DHCPv4 {
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	if dhcpLayer := p.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
		return dhcpLayer.(*layers.DHCPv4)
	}
	return nil // received packet is not DHCP
}

func isOffer(packet *layers.DHCPv4) bool {
	for _, option := range packet.Options {
		if option.Type == layers.DHCPOptMessageType && option.Length == 1 {
			return layers.DHCPMsgType(option.Data[0]) == layers.DHCPMsgTypeOffer
		}
	}
	return false
}

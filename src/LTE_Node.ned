package kyberaesproject;

import inet.node.inet.AdhocHost;
import inet.node.inet.StandardHost;
import inet.node.inet.WirelessHost;

module LTE_Node extends AdhocHost
{
    parameters:
        @display("i=device/laptop");
        numApps = 1; // Use one application
        app[0].typename = "LTEApp"; // Specify your application
        wlan[0].mac.opMode = "adhoc";
        // Other application parameters can be set here or in the network NED file
        // Ensure radio parameters are suitable for mobility
        wlan[0].radio.transmitter.power = 20mW;
        wlan[0].radio.receiver.sensitivity = -90dBm;
}

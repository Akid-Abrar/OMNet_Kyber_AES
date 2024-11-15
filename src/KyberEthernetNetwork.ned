package kyberaesproject;

import inet.node.ethernet.Eth100G;
import inet.common.scenario.ScenarioManager;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.Eth1G;
import inet.node.inet.StandardHost;
import inet.linklayer.ethernet.EthernetInterface;


network KyberEthernetNetwork
{
    parameters:
        @display("bgb=600,400");
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,50");
        }
        //        switch: EtherSwitch {
        //            @display("p=300,200");
        //        }
        nodeA: Ethernet_Node {
            @display("p=100,200");
        }
        nodeB: Ethernet_Node {
            @display("p=500,200");
        }
    connections allowunconnected:
        //        hostA.ethg++ <--> EthernetCable <--> switch.ethg++;
        //        hostB.ethg++ <--> EthernetCable <--> switch.ethg++;
        nodeA.port++ <--> Eth100G{length = 1000m;} <--> nodeB.port++;
}

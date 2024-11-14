package kyberaesproject;

import inet.common.scenario.ScenarioManager;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;
import inet.mobility.static.StationaryMobility;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211RadioMedium;
import kyberaesproject.LTE_Node;

network KyberLTENetwork
{
    parameters:
        @display("bgb=600,400");
    submodules:
        radioMedium: Ieee80211RadioMedium {
            @display("p=300,50");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,50");
        }
        visualizer: IntegratedCanvasVisualizer {
            @display("p=100,100");
        }
        scenarioManager: ScenarioManager {
            @display("p=500,50");
        }
        ueA: LTE_Node {
            @display("p=100,200");
            interfaces[0].ipv4.address = "10.0.0.1";
            interfaces[0].ipv4.netmask = "255.255.255.0";
            mobility.typename = "StationaryMobility";
            app[0].destAddr = "10.0.0.2";
            app[0].startTime = 1s;
        }
        ueB: LTE_Node {
            @display("p=500,200");
            interfaces[0].ipv4.address = "10.0.0.2";
            interfaces[0].ipv4.netmask = "255.255.255.0";
            mobility.typename = "StationaryMobility";
            app[0].destAddr = "10.0.0.1";
            app[0].startTime = 1s;
        }
    connections allowunconnected:
        // No wired connections; communication is over wireless
}

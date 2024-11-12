package kyberaesproject;

import inet.common.scenario.ScenarioManager;
import inet.visualizer.integrated.IntegratedCanvasVisualizer;
import inet.mobility.static.StationaryMobility;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import kyberaesproject.LTE_Node;

network KyberLTENetwork
{
    parameters:
        @display("bgb=600,400");
    submodules:
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
            app[0].destNode = "ueB"; // Set destination node for ueA
        }
        ueB: LTE_Node {
            @display("p=500,200");
            app[0].destNode = "ueA"; // Set destination node for ueB
        }
    connections allowunconnected:
        // No wired connections; communication is over wireless LTE
}

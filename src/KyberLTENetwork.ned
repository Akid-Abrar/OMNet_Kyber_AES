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
            mobilityVisualizer.displayRoute = true; // Optional: visualize movement
        }
        scenarioManager: ScenarioManager {
            @display("p=500,50");
        }
//        ueA: LTE_Node {
//            @display("p=100,200");
//            //mobility.typename = "StationaryMobility";
//            mobility.typename = "RandomWaypointMobility"; // Set mobility model
//            mobility.speed = uniform(5 mps, 10 mps);      // Speed range
//            mobility.updateInterval = 0.1s;               // Update interval
//            mobility.x = 100m;                            // Initial position
//            mobility.y = 200m;
//            interfaces[0].ipv4.address = "10.0.0.1";
//            interfaces[0].ipv4.netmask = "255.255.255.0";
//            app[0].destAddr = "10.0.0.2";
//            app[0].startTime = 1s;
//        }
//        ueB: LTE_Node {
//            @display("p=500,200");
//            //mobility.typename = "StationaryMobility";
//            mobility.typename = "RandomWaypointMobility";
//            mobility.speed = uniform(5 mps, 10 mps);
//            mobility.updateInterval = 0.1s;
//            mobility.x = 500m;
//            mobility.y = 200m;
//            interfaces[0].ipv4.address = "10.0.0.2";
//            interfaces[0].ipv4.netmask = "255.255.255.0";        
//            app[0].destAddr = "10.0.0.1";
//            app[0].startTime = 1s;
//        }
		ueA: LTE_Node {
        @display("p=100,200");
       	mobility.typename = "StationaryMobility";
        
//        mobility.typename = "RandomWaypointMobility";
//        mobility.speed = uniform(5 mps, 10 mps);
//        mobility.updateInterval = 0.1s;
//    
//        // Set the constraint area
//        mobility.constraintAreaMinX = 0m;
//        mobility.constraintAreaMinY = 0m;
//        mobility.constraintAreaMinZ = 0m;
//        mobility.constraintAreaMaxX = 1000m;
//        mobility.constraintAreaMaxY = 1000m;
//        mobility.constraintAreaMaxZ = 0m; // For 2D movement, Z can be 0
//    
//        // Set initial position using initialX and initialY
//        mobility.initialX = 100m;
//        mobility.initialY = 200m;
//        mobility.initialZ = 0m;
    
        interfaces[0].ipv4.address = "10.0.0.1";
        interfaces[0].ipv4.netmask = "255.255.255.0";
        app[0].destAddr = "10.0.0.2";
        app[0].startTime = 1s;
    }
    
    ueB: LTE_Node {
        @display("p=500,200");
        mobility.typename = "RandomWaypointMobility";
        mobility.speed = uniform(5 mps, 10 mps);
        mobility.updateInterval = 0.5s;
    
        // Set the same constraint area
        mobility.constraintAreaMinX = 0m;
        mobility.constraintAreaMinY = 0m;
        mobility.constraintAreaMinZ = 0m;
        mobility.constraintAreaMaxX = 1000m;
        mobility.constraintAreaMaxY = 1000m;
        mobility.constraintAreaMaxZ = 0m;
    
        // Set initial position
        mobility.initialX = 500m;
        mobility.initialY = 200m;
        mobility.initialZ = 0m;
    
        interfaces[0].ipv4.address = "10.0.0.2";
        interfaces[0].ipv4.netmask = "255.255.255.0";
        app[0].destAddr = "10.0.0.1";
        app[0].startTime = 1s;
    }
    connections allowunconnected:
        // No wired connections; communication is over wireless
}

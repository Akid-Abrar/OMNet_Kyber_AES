package kyberaesproject;

import inet.node.inet.StandardHost;

module LTE_Node extends StandardHost
{
    parameters:
        @display("i=device/laptop");
        mobility.typename = default("StationaryMobility");
        numApps = 1; // Use one application
        app[0].typename = "kyberaesproject.LTEApp"; // Specify your application
        // Set any additional parameters for your application here
}

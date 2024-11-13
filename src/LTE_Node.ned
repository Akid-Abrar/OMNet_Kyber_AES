package kyberaesproject;

import inet.node.inet.StandardHost;

module LTE_Node extends StandardHost
{
    parameters:
        @display("i=device/laptop");
        numApps = 1; // Use one application
        app[0].typename = "kyberaesproject.LTEApp"; // Specify your application
        // Other application parameters can be set here or in the network NED file
}

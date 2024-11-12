package kyberaesproject;

import inet.applications.contract.IApp;

simple LTEApp like IApp
{
    parameters:
        double startTime @unit(s) = default(0s); // Time to start the application
        string destNode; // Name of the destination node
        int localPort = default(1000); // Local UDP port
        int destPort = default(1000);  // Destination UDP port
        @display("i=block/app");
    gates:
        input socketIn;
        output socketOut;
}

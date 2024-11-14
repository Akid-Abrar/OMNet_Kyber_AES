package kyberaesproject;

import inet.applications.contract.IApp;

simple LTEApp like IApp
{
    parameters:
       	@class(::LTEApp);
        @display("i=block/app");
        double startTime @unit(s) = default(1s);
        string destAddr @mutable; // Destination IP address
        int localPort = default(1000);
        int destPort = default(1000);
    gates:
        input socketIn;
        output socketOut;
}

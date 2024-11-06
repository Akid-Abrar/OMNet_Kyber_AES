package kyberaesproject;

network KyberNetwork
{
    submodules:
        nodeA: Node {
            @display("p=100,200");
        }
        nodeB: Node {
            @display("p=300,200");
        }
    connections:
        nodeA.outPort --> {  delay = 100ms; } --> nodeB.inPort;
        nodeB.outPort --> {  delay = 100ms; } --> nodeA.inPort;
}

//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

package kyberaesproject;

import inet.common.scenario.ScenarioManager;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;
import inet.linklayer.ethernet.EtherSwitch;
import inet.linklayer.ethernet.EthernetInterface;
import inet.physicallayer.ethernet.EthernetCable;

network KyberEthernetNetwork
{
    parameters:
        @display("bgb=600,400");
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,50");
        }
        switch: EtherSwitch {
            @display("p=300,200");
        }
        hostA: StandardHost {
            @display("p=100,350");
        }
        hostB: StandardHost {
            @display("p=500,350");
        }
    connections allowunconnected:
        hostA.ethg++ <--> EthernetCable <--> switch.ethg++;
        hostB.ethg++ <--> EthernetCable <--> switch.ethg++;
}
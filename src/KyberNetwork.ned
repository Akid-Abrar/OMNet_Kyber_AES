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

#  Imports all functions and classes from Scapy, allowing us to use its packet manipulation capabilities.
from scapy.all import *
def capture_packets(packet_count):
    # Define the filename to save captured packets
    filename = "captured_packets.pcap"
    # Print a message indicating the number of packets to capture and the filename
    print(f"Capturing {packet_count} packets and saving to '{filename}'...")

    # Use the sniff function from Scapy to capture packets
    # `count` specifies the number of packets to capture
    packets = sniff(count=packet_count)
    # Save captured packets to a pcap file using wrpcap function
    # `filename` specifies the name of the pcap file to save
    # `packets` is the list of packets captured by sniff
    wrpcap(filename, packets)
    # Print a message confirming the successful saving of packets to the file1
    print(f"Packets saved successfully to '{filename}'.")

if __name__ == "__main__":
    # Prompt the user to input the number of packets to capture
    packet_count = int(input("Enter the number of packets to capture: "))
    # Call the capture_packets function with user-provided packet_count
    capture_packets(packet_count)


#include <iostream>

#include "KeInterface.h"




int main()
{
	KeInterface Driver("\\\\.\\kernelhop");

	// Get address of client.dll & pid of csgo from our driver
	DWORD ProcessId = Driver.GetTargetPid();
	DWORD ClientAddress = Driver.GetClientModule();

	// Get address of localplayer
	DWORD LocalPlayer = Driver.ReadVirtualMemory<DWORD>(ProcessId, ClientAddress + LOCAL_PLAYER, sizeof(ULONG));

	// address of inground
	DWORD InGround = Driver.ReadVirtualMemory<DWORD>(ProcessId,
		LocalPlayer + FFLAGS, sizeof(ULONG));

	// check that addresses were found


	std::cout << "Found csgo Process Id: " << ProcessId << std::endl;
	std::cout << "Found client.dll ClientBase: 0x" << std::uppercase
		<< std::hex << ClientAddress << std::endl;
	std::cout << "Found LocalPlayer in client.dll: 0x" << std::uppercase
		<< std::hex << LocalPlayer << std::endl;
	std::cout << "Found PlayerInGround: 0x" << std::uppercase
		<< std::hex << InGround << std::endl;

	while (true)
	{
		// Constantly check if player is in ground
		DWORD InGround = Driver.ReadVirtualMemory<DWORD>(ProcessId, LocalPlayer + FFLAGS, sizeof(ULONG));
		// Check if space is down & player is in ground
		if ((GetAsyncKeyState(VK_SPACE) & 0x8000) && (InGround & 1 == 1))
		{
			// Jump
			Driver.WriteVirtualMemory(ProcessId, ClientAddress + FORCE_JUMP, 0x5, 8);
			Sleep(50);
			// Restore
			Driver.WriteVirtualMemory(ProcessId, ClientAddress + FORCE_JUMP, 0x4, 8);
			
		}
		Sleep(10);
	}
    return 0;
}


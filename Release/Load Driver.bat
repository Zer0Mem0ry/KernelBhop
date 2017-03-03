start D:\Projects\KernelBhop\Release\dsefix.exe
timeout /t 2
sc create csgo binpath=D:\Projects\KernelBhop\Release\Driver.sys type=kernel
sc start csgo
timeout /t 5
start D:\Projects\KernelBhop\Release\dsefix.exe -e
timeout /t 2
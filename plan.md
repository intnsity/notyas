Create an implementation of BigDice https://github.com/intnsity/BigDice which runs on a waveshare  esp32-p4-wifi6-touch-lcd-4b - generate a custom kernel for the waveshare device (bootstrap with open source from the manufacturer) - the outcome of our version will be gpl3 OS to flash for btc hardware wallet. Being a secure airgapped btc wallet is the ultimate outcome - the only apps or features should be those which allow the user to read the bootroom hashes or verify the security of the device, wifi or wireless drivers should be turned off at the kernel level and not accessible after flash. I want only solid code. I want results in rust where possible, don't worry about some effort to write in rust, but no need to try hand-wrapping the whole OS or anything too crazy unless that is easier. Our UI/UX should have a terminal looking theme using IBM Plex Sans or "\\172.16.0.9\bear\code\YellowBGs.md" theming and not too modern in fact very simple is the goal. 

BigDice already works really well and has most features we could want. SeedSigner also has incredible features. https://github.com/SeedSigner

You have a dev device available to you:     
    ESP-ROM:esp32p4-eco2-20240710
    Build:Jul 10 2024
    rst:0x1 (POWERON),boot:0x307 (DOWNLOAD(USB/UART0/SPI))
    waiting for download

All of your work product is to live in \\172.16.0.9\bear\code\btc\dice_generator\bigdice32 and we will eventually release your work product to the official bigdice github somehow. 

You are allowed to review \\172.16.0.9\bear\code\btc\dice_generator and allowed to go to source documentation for your work. Use opus ultracode or sonnet ultracode subagents as needed - you are the orchestrator and the manager - your job is to design, test, and validate code. Keep all code extremely simple and cryptographic / opsec security focused - use solid code and set versioning to 0.1.0 to begin with. Be able to rollback if you see regressions. You can use the local pc but keep your work in \\172.16.0.9\bear\code\btc\dice_generator\bigdice32
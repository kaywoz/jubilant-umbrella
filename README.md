# jubilant-umbrella

Repo for generic setups of modern Windows machines according to what I need.

Some sets for Win10, Server etc heavily re-using old code from the furthest reaches of the galaxy. 

I dont excuse ugly, since I'm not a coder.

Use at your own risk, do your due diligence etc.

** For use on workgroup machines only, for test/dev/one-off or standalone builds of Windows.
** These are primarily to be used for VM templating, as compacting the OS and updating the OS is such a bore to do in a recurring way...
**  Needs script execution enabled since it's a script (duh), just use "Set-ExecutionPolicy Bypass -Scope CurrentUser -Force" or similar syntax beforehand.

* Sets hostname, Private network, creates some standard dir's with Defender exclusions.
* Enables PSremoting as a workgroup machine.
* Enables RDP with firewall exclusion sets.
* Installs Boxstarter and Chocolatey and some standard packages.
* Tweaks the UI and Explorer behaviour so the adminuser does not break into a mental hissy fit.
* Preps for WSL.
* Removes some unnecessary stuff via DISM and compacts the OS so that Windows runs even slower. (but you're running this on pure NVME goodness, right?)
* Leaves the heavy lifting to other scripts which are written by people who know their shit.

/ka

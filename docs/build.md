# Build and Program (VS Code)

This project is built and programmed using the ModusToolbox VS Code extension.

## Requirements
- ModusToolbox 3.6 (tested). Project creation performed with ModusToolbox 3.6.
- VS Code with the ModusToolbox extension installed.
- KIT_PSE84_EVAL_EPC2 connected via KitProg3 USB.

## Steps
1. Open the project folder in VS Code. When prompted, allow the ModusToolbox extension to install required tools.

   ![ModusToolbox extension tool installation](../images/build-step-01-tools-install.jpg)

2. Add the bootloader for this workspace using **Add Bootloader**. This creates `proj_bootloader` and pulls required dependencies.

   ![Add Bootloader action in ModusToolbox](../images/build-step-02-add-bootloader.jpg)

3. Confirm that `proj_bootloader` appears in the workspace after the installation completes.

   ![Workspace with proj_bootloader](../images/build-step-03-bootloader-workspace.jpg)

4. Build and program the board using the ModusToolbox **Build** and **Program** actions.

   ![Build and program actions](../images/build-step-04-build-program.jpg)

5. Open a serial terminal (115200 baud, 8N1) to check the demo output.

## Notes
- If Add Bootloader or Build fails, run **Clean** and try again.
- In some cases, you may need to run **Add Bootloader** a second time to complete dependency downloads after `proj_bootloader` is created.

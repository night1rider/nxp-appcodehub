#!/bin/bash

# Function to sanitize the directory name by removing the trailing slash if it exists
sanitize_directory() {
    local dir_name="$1"
    # Remove trailing slash using string manipulation
    sanitized_dir="${dir_name%/}"
    echo "$sanitized_dir"
}

# Create the .vscode directory if it doesn't exist
create_vscode_directory() {
    local subfolder="$1"
    if [ -d "$subfolder/.vscode" ]; then
        echo "Error: The directory '$subfolder/.vscode' already exists."
        exit 1
    fi
    mkdir "$subfolder/.vscode"
    echo "Created .vscode directory in $subfolder."
}

# Create cmake-kits.json
create_cmake_kits() {
    local subfolder="$1"
    cat <<EOF > "$subfolder/.vscode/cmake-kits.json"
[
  {
    "name": "Zephyr build tool",
    "environmentVariables": {
      "ZEPHYR_BASE": "",
      "ZEPHYR_SDK_INSTALL_DIR": ""
    },
    "cmakeSettings": {
      "BOARD": "frdm_mcxn947/mcxn947/cpu0"
    },
    "keep": true
  }
]
EOF
    echo "cmake-kits.json created."
}

# Create cmake-variants.json
create_cmake_variants() {
    local subfolder="$1"
    cat <<EOF > "$subfolder/.vscode/cmake-variants.json"
{
  "build_type": {
    "default": "debug",
    "choices": {
      "debug": {
        "short": "debug",
        "buildType": "debug"
      },
      "release": {
        "short": "release",
        "buildType": "release"
      }
    }
  }
}
EOF
    echo "cmake-variants.json created."
}

# Create launch.json
create_launch_json() {
    local subfolder="$1"
    cat <<EOF > "$subfolder/.vscode/launch.json"
{
  "configurations": [
    {
      "type": "cppdbg",
      "name": "Debug project configuration",
      "request": "launch",
      "cwd": "\${workspaceRoot}",
      "MIMode": "gdb",
      "setupCommands": [
        {"text": "set remotetimeout 600"},
        {"text": "set debug-file-directory"}
      ],
      "program": "",
      "miDebuggerServerAddress": "",
      "variables": {
        "mcuxStopAtSymbol": "main",
        "mcuxSerialNumber": "",
        "mcuxAttach": "false",
        "mcuxRemoteProbeType": "",
      },
      "logging": {
        "engineLogging": false
      }
    }
  ]
}
EOF
    echo "launch.json created."
}

# Create mcuxpresso-tools.json
create_mcuxpresso_tools() {
    local subfolder="$1"
    cat <<EOF > "$subfolder/.vscode/mcuxpresso-tools.json"
{
  "version": "1.1",
  "toolchainPath": "",
  "toolchainVersion": "",
  "linkedProjects": [],
  "trustZoneType": "none",
  "multicoreType": "none",
  "debug": {
    "linkserver": {},
    "pemicro": {},
    "segger": {}
  },
  "projectType": "zephyr-workspace",
  "sdk": {
    "boardId": "frdm_mcxn947/mcxn947/cpu0",
    "version": "",
    "path": ""
  }
}
EOF
    echo "mcuxpresso-tools.json created."
}

# Create settings.json
create_settings_json() {
    local subfolder="$1"
    cat <<EOF > "$subfolder/.vscode/settings.json"
{
  "cmake.configureOnOpen": false,
  "C_Cpp.errorSquiggles": "disabled",
  "cmake.preferredGenerators": [
    "Ninja",
    "Unix Makefiles",
    "MinGW Makefiles"
  ],
  "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools",
  "cmake.sourceDirectory": "\${workspaceFolder}"
}
EOF
    echo "settings.json created."
}

# Main function to orchestrate the creation of all files
create_vscode_configs() {
    local subfolder="$(sanitize_directory "$1")"

    # Check if subfolder name was provided
    if [ -z "$subfolder" ]; then
        echo "Error: Please provide a subfolder name as an argument."
        exit 1
    fi

    # Check if the input directory exists
    if [ ! -d "$subfolder" ]; then
        echo "Error: The directory '$subfolder' does not exist."
        exit 1
    fi

    create_vscode_directory "$subfolder"
    create_cmake_kits "$subfolder"
    create_cmake_variants "$subfolder"
    create_launch_json "$subfolder"
    create_mcuxpresso_tools "$subfolder"
    create_settings_json "$subfolder"
}

# Call the main function with the first script argument
create_vscode_configs "$1"


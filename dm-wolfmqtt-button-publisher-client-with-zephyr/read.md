```mermaid
flowchart TD
    A(Start) --> B[Initialize Network]
    B --> C[Initialize MQTT Client]
    C --> D[Set MQTT Connection Parameters]
    D --> E[Setup TLS for AWS IoT]
    E --> F[Connect via MqttClient_NetConnect]
    F --> G[Send MQTT Connect Packet]
    G --> H{Connection Successful?}
    H -- Yes --> I[Subscribe to Topics]
    H -- No --> Z[Handle Connection Error]
    I --> J[Publish to Topics]
    J --> K[Wait for Messages]
    K --> L{Messages Received?}
    L -- Yes --> M[Handle Messages]
    L -- No --> N[Check for Commands]
    M --> N
    N -- Timeout or Command --> O{Disconnect?}
    O -- Yes --> P[Disconnect]
    O -- No --> K
    P --> Q[Cleanup Resources]
    Q --> R[End]
    Z --> Q

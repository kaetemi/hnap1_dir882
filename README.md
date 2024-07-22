## Usage Example

```js
const HNAP1Client = require('./hnap1-client');

async function main() {
  const client = new HNAP1Client('192.168.0.1', 'Admin', '');

  try {
    await client.login();
    console.log('Login successful');

    const deviceSettings = await client.getDeviceSettings();
    console.log('Device Settings:', deviceSettings);

    const wanSettings = await client.getWanSettings();
    console.log('WAN Settings:', wanSettings);

    const wireless24Settings = await client.getWirelessSettings('RADIO_2.4GHz');
    console.log('2.4GHz Wireless Settings:', wireless24Settings);

    const wireless5Settings = await client.getWirelessSettings('RADIO_5GHz');
    console.log('5GHz Wireless Settings:', wireless5Settings);

    const connectedClients = await client.getConnectedClients();
    console.log('Connected Clients:', connectedClients);

    // Uncomment the following line to reboot the router (use with caution)
    // const rebootResult = await client.reboot();
    // console.log('Reboot Result:', rebootResult);

  } catch (error) {
    console.error('An error occurred:', error);
  }
}

// Run the main function
main();
```

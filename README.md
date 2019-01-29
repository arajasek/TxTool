# TxTool
Uses the Aion Java API to sign transactions offline, and then send them

Clone the project 

`git clone https://github.com/arajasek/TxTool.git`
`cd TxTool`

Build the project

`./gradlew build`

Run the tool

`./gradlew run --args "<url> <privateKey> <toAddress> <value> <data> <type>"`,

where `url` is the URL of the node accepting Java API requests,

`privateKey` is the private key of the account signing the transaction. This should be 32 bytes long, and should not start with 0x,

`toAddress` is the destination address of the transaction, without the 0x,

`value` is the value to be transferred, as a hex string (no 0x),

`data` to be sent, as a hex string (no 0x),

`type` of the transaction is `1` for FVM transactions, `f` for AVM.

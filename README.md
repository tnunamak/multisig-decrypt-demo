* ibm.go: uses IBM/TSS, which wraps tss-lib, to demonstrate a simple DKG threshold signature scheme, with share refresh
    * `go run ibm.go`
* rsa.go: uses niclabs/tcrsa to demonstrate a simple DKG threshold signature scheme, and begins to model a data provider/consumer encryption/decryption scheme (incomplete)
    * `go run rsa.go`
* main.go: uses bnb-chain/tss-lib to demonstrate a simple DKG threshold signature scheme (does not work)
    * `go run main.go`

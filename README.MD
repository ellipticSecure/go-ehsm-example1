### This simple example demonstrates how to use the eHSM Hardware Security Module to perform elliptic curve cryptography.

For updated documentation, see [the how-to](https://ellipticsecure.com/ehsm/how-to/2019/01/23/ehsm-go-ecc-example.html).
#### Prerequisites: an initialized eHSM with a user password set.

#### Test and build instructions

Setup your Go environment as usual, change main.go if needed and then:

```bash
go get github.com/ellipticSecure/go-ehsm-example1
go install github.com/ellipticSecure/go-ehsm-example1
./bin/go-ehsm-example1
```

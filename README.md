# Knocker - Endpoint Security Assessment Framework .

#####  Knocker is an EndPoint Security Assessment Framework .User can create different types of executable files that will help to assess endpoints by trying different techniques to bypass endpoint protections including AntiVirus .Current beta version has 6 options 3 Powershell and 3 Go Lang Techniques .

## Getting Started

##### git clone https://github.com/diljithishere/knocker.git
##### cd knocker/src
#### Open apiconfig.cfg under src\config folder and update your IP address 
#### set GOARCH=386
#### go build knocker.go
#### Run exe 
##### > knocker.exe

##### Use your browser to access : http://localhost:8085
#### Virtual Alloc Injection : Inject windows/meterpreter/reverse_http powershell shell code, all other options need only RHOST and RPORT


### Prerequisites

#### Go 1.9

#### References : SET tool kit and Veil Framework.

## Built With
Go Lang

## Author

* **Diljith S** - *Initial work* - (https://github.com/diljithishere)

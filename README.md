# P100-go
Library for communicating with Tapo P100 smart plug.

## Example usage:
```go
plug := p100.New("192.168.0.100", "example@gmail.com", "password")

if err := device.Handshake(); err != nil {
  log.Panic(err)
}

if err := device.Login(); err != nil {
  log.Panic(err)
}

device.Switch(false)

deviceInfo, err := device.GetDeviceInfo()
```

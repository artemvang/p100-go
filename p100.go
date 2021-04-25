package p100

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const Timeout = time.Second * 15

type P100Status struct {
	ErrorCode int `json:"error_code"`
	Result    struct {
		DeviceID           string `json:"device_id"`
		FWVersion          string `json:"fw_ver"`
		HWVersion          string `json:"hw_ver"`
		Type               string `json:"type"`
		Model              string `json:"model"`
		MAC                string `json:"mac"`
		HWID               string `json:"hw_id"`
		FWID               string `json:"fw_id"`
		OEMID              string `json:"oem_id"`
		Specs              string `json:"specs"`
		DeviceON           bool   `json:"device_on"`
		OnTime             int    `json:"on_time"`
		OverHeated         bool   `json:"overheated"`
		Nickname           string `json:"nickname"`
		Location           string `json:"location"`
		Avatar             string `json:"avatar"`
		Longitude          int    `json:"longitude"`
		Latitude           int    `json:"latitude"`
		HasSetLocationInfo bool   `json:"has_set_location_info"`
		IP                 string `json:"ip"`
		SSID               string `json:"ssid"`
		SignalLevel        int    `json:"signal_level"`
		RSSI               int    `json:"rssi"`
		Region             string `json:"Europe/Kiev"`
		TimeDiff           int    `json:"time_diff"`
		Lang               string `json:"lang"`
	} `json:"result"`
}

type P100Device struct {
	ip              string
	encodedEmail    string
	encodedPassword string
	cipher          *P100Cipher
	sessionID       string
	token           *string
	client          *http.Client
}

func New(ip, email, password string) *P100Device {
	h := sha1.New()
	h.Write([]byte(email))
	digest := hex.EncodeToString(h.Sum(nil))
	encodedEmail := base64.StdEncoding.EncodeToString([]byte(digest))
	encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))

	return &P100Device{
		ip:              ip,
		encodedEmail:    encodedEmail,
		encodedPassword: encodedPassword,
		client:          &http.Client{Timeout: Timeout},
	}
}

func (d *P100Device) GetURL() string {
	if d.token == nil {
		return fmt.Sprintf("http://%s/app", d.ip)
	} else {
		return fmt.Sprintf("http://%s/app?token=%s", d.ip, *d.token)
	}
}

func (d *P100Device) DoRequest(payload []byte) ([]byte, error) {
	encryptedPayload := base64.StdEncoding.EncodeToString(d.cipher.Encrypt(payload))
	securedPayload, _ := json.Marshal(map[string]interface{}{
		"method": "securePassthrough",
		"params": map[string]interface{}{
			"request": encryptedPayload,
		},
	})

	req, _ := http.NewRequest("POST", d.GetURL(), bytes.NewBuffer(securedPayload))
	req.Header.Set("Cookie", d.sessionID)
	req.Close = true

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var jsonResp struct {
		ErrorCode int `json:"error_code"`
		Result    struct {
			Response string `json:"response"`
		} `json:"result"`
	}

	json.NewDecoder(resp.Body).Decode(&jsonResp)

	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return nil, err
	}

	encryptedResponse, _ := base64.StdEncoding.DecodeString(jsonResp.Result.Response)

	return d.cipher.Decrypt(encryptedResponse), nil
}

func (d *P100Device) CheckErrorCode(errorCode int) error {
	if errorCode != 0 {
		return errors.New(fmt.Sprintf("Got error code %d", errorCode))
	}

	return nil
}

func (d *P100Device) Handshake() (err error) {
	privKey, pubKey := GenerateRSAKeys()

	pubPEM := DumpRSAPEM(pubKey)
	payload, _ := json.Marshal(map[string]interface{}{
		"method": "handshake",
		"params": map[string]interface{}{
			"key":             string(pubPEM),
			"requestTimeMils": 0,
		},
	})

	resp, err := http.Post(d.GetURL(), "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return
	}

	defer resp.Body.Close()

	var jsonResp struct {
		ErrorCode int `json:"error_code"`
		Result    struct {
			Key string `json:"key"`
		} `json:"result"`
	}

	json.NewDecoder(resp.Body).Decode(&jsonResp)
	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return
	}

	encryptedEncryptionKey, _ := base64.StdEncoding.DecodeString(jsonResp.Result.Key)
	encryptionKey, _ := rsa.DecryptPKCS1v15(rand.Reader, privKey, encryptedEncryptionKey)
	d.cipher = &P100Cipher{
		key: encryptionKey[:16],
		iv:  encryptionKey[16:],
	}

	d.sessionID = strings.Split(resp.Header.Get("Set-Cookie"), ";")[0]

	return
}

func (d *P100Device) Login() (err error) {
	if d.cipher == nil {
		return errors.New("Handshake was not performed")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"method": "login_device",
		"params": map[string]interface{}{
			"username": d.encodedEmail,
			"password": d.encodedPassword,
		},
	})

	payload, err = d.DoRequest(payload)
	if err != nil {
		return
	}

	var jsonResp struct {
		ErrorCode int `json:"error_code"`
		Result    struct {
			Token string `json:"token"`
		} `json:"result"`
	}

	json.NewDecoder(bytes.NewBuffer(payload)).Decode(&jsonResp)
	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return
	}

	d.token = &jsonResp.Result.Token
	return
}

func (d *P100Device) Switch(status bool) (err error) {
	if d.token == nil {
		return errors.New("Login was not performed")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"method": "set_device_info",
		"params": map[string]interface{}{
			"device_on": status,
		},
	})

	payload, err = d.DoRequest(payload)
	if err != nil {
		return
	}

	var jsonResp struct {
		ErrorCode int `json:"error_code"`
	}

	json.NewDecoder(bytes.NewBuffer(payload)).Decode(&jsonResp)
	if err = d.CheckErrorCode(jsonResp.ErrorCode); err != nil {
		return
	}

	if jsonResp.ErrorCode != 0 {
		return errors.New(fmt.Sprintf("Got error code %d", jsonResp.ErrorCode))
	}

	return
}

func (d *P100Device) GetDeviceInfo() (*P100Status, error) {
	if d.token == nil {
		return nil, errors.New("Login was not performed")
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"method": "get_device_info",
	})

	payload, err := d.DoRequest(payload)
	if err != nil {
		return nil, err
	}

	status := &P100Status{}

	json.NewDecoder(bytes.NewBuffer(payload)).Decode(status)
	if err = d.CheckErrorCode(status.ErrorCode); err != nil {
		return nil, err
	}

	nicknameEncoded, _ := base64.StdEncoding.DecodeString(status.Result.Nickname)
	status.Result.Nickname = string(nicknameEncoded)

	SSIDEncoded, _ := base64.StdEncoding.DecodeString(status.Result.SSID)
	status.Result.SSID = string(SSIDEncoded)

	return status, nil
}

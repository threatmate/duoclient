package duoclient

const (
	StatusActive          = "active"
	StatusBypass          = "bypass"
	StatusDisabled        = "disabled"
	StatusLockedOut       = "locked out"
	StatusPendingDeletion = "pending deletion"
)

type User struct {
	UserID           string  `json:"user_id"`
	Username         string  `json:"username"`
	RealName         string  `json:"realname"`
	Email            string  `json:"email"`
	Status           string  `json:"status"`
	IsEnrolled       bool    `json:"is_enrolled"`
	EnableAutoPrompt bool    `json:"enable_auto_prompt"`
	LastLogin        float64 `json:"last_login"`
	Phones           []Phone `json:"phones"`
	Groups           []Group `json:"groups"`
}

type Phone struct {
	PhoneID          string   `json:"phone_id"`
	Number           string   `json:"number"`
	Activated        bool     `json:"activated"`
	Capabilities     []string `json:"capabilities"`
	Encrypted        string   `json:"encrypted"`
	Extension        string   `json:"extension"`
	Fingerprint      string   `json:"fingerprint"`
	LastSeen         string   `json:"last_seen"`
	Model            string   `json:"model"`
	Name             string   `json:"name"`
	Platform         string   `json:"platform"`
	Screenlock       string   `json:"screenlock"`
	SMSPasscodesSent bool     `json:"sms_passcodes_sent"`
	Tampered         string   `json:"tampered"`
	Type             string   `json:"type"`
}

type Group struct {
	GroupID          string `json:"group_id"`
	Name             string `json:"name"`
	Description      string `json:"desc"`
	Status           string `json:"status"`
	MobileOTPEnabled bool   `json:"mobile_otp_enabled"`
	PushEnabled      bool   `json:"push_enabled"`
	SMSEnabled       bool   `json:"sms_enabled"`
	VoiceEnabled     bool   `json:"voice_enabled"`
}

type GetUsersResponse struct {
	Response []User   `json:"response"`
	Stat     string   `json:"stat"`
	Metadata Metadata `json:"metadata,omitempty"`
}

type Metadata struct {
	TotalObjects int  `json:"total_objects"`
	NextOffset   *int `json:"next_offset,omitempty"`
	PrevOffset   *int `json:"prev_offset,omitempty"`
}

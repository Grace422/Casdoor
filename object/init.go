// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"encoding/gob"
	"fmt"
	"os"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/go-webauthn/webauthn/webauthn"
)

func InitDb() {
	existed := initBuiltInOrganization()
	if !existed {
		initBuiltInPermission()
		initBuiltInProvider()
		initBuiltInUser()
		initBuiltInApplication()
		initBuiltInCert()
		initBuiltInLdap()
	}

	existed = initBuiltInApiModel()
	if !existed {
		initBuiltInApiAdapter()
		initBuiltInApiEnforcer()
		initBuiltInUserModel()
		initBuiltInUserAdapter()
		initBuiltInUserEnforcer()
	}

	initWebAuthn()
}

func getBuiltInAccountItems() []*AccountItem {
	return []*AccountItem{
		{Name: "Organization", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "ID", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
		{Name: "Name", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Display name", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Avatar", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "User type", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Password", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Email", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Phone", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Country code", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Country/Region", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Location", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Affiliation", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Title", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Homepage", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Bio", Visible: true, ViewRule: "Public", ModifyRule: "Self"},
		{Name: "Tag", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Signup application", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "Roles", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
		{Name: "Permissions", Visible: true, ViewRule: "Public", ModifyRule: "Immutable"},
		{Name: "Groups", Visible: true, ViewRule: "Public", ModifyRule: "Admin"},
		{Name: "3rd-party logins", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Properties", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Is grace", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Is forbidden", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Is deleted", Visible: true, ViewRule: "Admin", ModifyRule: "Admin"},
		{Name: "Multi-factor authentication", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "WebAuthn credentials", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "Managed accounts", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
		{Name: "MFA accounts", Visible: true, ViewRule: "Self", ModifyRule: "Self"},
	}
}

func initBuiltInOrganization() bool {
	organization, err := getOrganization("grace", "Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if organization != nil {
		return true
	}

	organization = &Organization{
		Owner:              "grace",
		Name:               "Nzhinusoft",
		CreatedTime:        util.GetCurrentTime(),
		DisplayName:        "Nzhinusoft Organization",
		WebsiteUrl:         "https://nzhinusoft.com",
		Favicon:            fmt.Sprintf("%s/img/casbin/favicon.ico", conf.GetConfigString("staticBaseUrl")),
		PasswordType:       "plain",
		PasswordOptions:    []string{"AtLeast6"},
		CountryCodes:       []string{"US", "ES", "FR", "DE", "GB", "CN", "JP", "KR", "VN", "ID", "SG", "IN", "CM"},
		DefaultAvatar:      fmt.Sprintf("%s/img/casbin.svg", conf.GetConfigString("staticBaseUrl")),
		Tags:               []string{},
		Languages:          []string{"en", "fr"},
		InitScore:          2000,
		AccountItems:       getBuiltInAccountItems(),
		EnableSoftDeletion: false,
		IsProfilePublic:    false,
		UseEmailAsUsername: false,
		EnableTour:         true,
	}
	_, err = AddOrganization(organization)
	if err != nil {
		panic(err)
	}

	return false
}

func initBuiltInUser() {
	user, err := getUser("Nzhinusoft", "grace")
	if err != nil {
		panic(err)
	}
	if user != nil {
		return
	}

	user = &User{
		Owner:             "Nzhinusoft",
		Name:              "grace",
		CreatedTime:       util.GetCurrentTime(),
		Id:                util.GenerateId(),
		Type:              "normal-user",
		Password:          "password",
		DisplayName:       "Grace",
		Avatar:            fmt.Sprintf("%s/img/casbin.svg", conf.GetConfigString("staticBaseUrl")),
		Email:             "grace@example.com",
		Phone:             "12345678910",
		CountryCode:       "CM",
		Address:           []string{},
		Affiliation:       "Example Inc.",
		Tag:               "staff",
		Score:             2000,
		Ranking:           1,
		IsAdmin:           true,
		IsForbidden:       false,
		IsDeleted:         false,
		SignupApplication: "app-Nzhinusoft",
		CreatedIp:         "127.0.0.1",
		Properties:        make(map[string]string),
	}
	_, err = AddUser(user)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApplication() {
	application, err := getApplication("grace", "app-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if application != nil {
		return
	}

	application = &Application{
		Owner:          "grace",
		Name:           "app-Nzhinusoft",
		CreatedTime:    util.GetCurrentTime(),
		DisplayName:    "Nzhinusoft",
		// Logo:           fmt.Sprintf("%s/img/casdoor-logo_1185x256.png", conf.GetConfigString("staticBaseUrl")),
		Logo:           "https://nzhinusoft.com/assets/img/Nztrfinal.png",
		HomepageUrl:    "https://nzhinusoft.com",
		Organization:   "Nzhinusoft",
		Cert:           "cert-Nzhinusoft",
		EnablePassword: true,
		EnableSignUp:   true,
		Providers: []*ProviderItem{
			{Name: "provider_captcha_default", CanSignUp: false, CanSignIn: false, CanUnlink: false, Prompted: false, SignupGroup: "", Rule: "None", Provider: nil},
		},
		SigninMethods: []*SigninMethod{
			{Name: "Password", DisplayName: "Password", Rule: "All"},
			// {Name: "Verification code", DisplayName: "Verification code", Rule: "All"},
			// {Name: "WebAuthn", DisplayName: "WebAuthn", Rule: "None"},
			// {Name: "Face ID", DisplayName: "Face ID", Rule: "None"},
		},
		SignupItems: []*SignupItem{
			{Name: "ID", Visible: false, Required: true, Prompted: false, Rule: "Random"},
			{Name: "Username", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Display name", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Password", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Confirm password", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Email", Visible: true, Required: true, Prompted: false, Rule: "Normal"},
			{Name: "Phone", Visible: true, Required: true, Prompted: false, Rule: "None"},
			{Name: "Agreement", Visible: true, Required: true, Prompted: false, Rule: "None"},
		},
		Tags:          []string{},
		RedirectUris:  []string{},
		TokenFormat:   "JWT",
		TokenFields:   []string{},
		ExpireInHours: 168,
		FormOffset:    2,
	}
	_, err = AddApplication(application)
	if err != nil {
		panic(err)
	}
}

func readTokenFromFile() (string, string) {
	pemPath := "./object/token_jwt_key.pem"
	keyPath := "./object/token_jwt_key.key"
	pem, err := os.ReadFile(pemPath)
	if err != nil {
		return "", ""
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return "", ""
	}
	return string(pem), string(key)
}

func initBuiltInCert() {
	tokenJwtCertificate, tokenJwtPrivateKey := readTokenFromFile()
	cert, err := getCert("grace", "cert-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if cert != nil {
		return
	}

	cert = &Cert{
		Owner:           "grace",
		Name:            "cert-Nzhinusoft",
		CreatedTime:     util.GetCurrentTime(),
		DisplayName:     "Nzhinusoft Cert",
		Scope:           "JWT",
		Type:            "x509",
		CryptoAlgorithm: "RS256",
		BitSize:         4096,
		ExpireInYears:   20,
		Certificate:     tokenJwtCertificate,
		PrivateKey:      tokenJwtPrivateKey,
	}
	_, err = AddCert(cert)
	if err != nil {
		panic(err)
	}
}

func initBuiltInLdap() {
	ldap, err := GetLdap("ldap-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if ldap != nil {
		return
	}

	ldap = &Ldap{
		Id:         "ldap-Nzhinusoft",
		Owner:      "Nzhinusoft",
		ServerName: "BuildIn LDAP Server",
		Host:       "example.com",
		Port:       389,
		Username:   "cn=buildin,dc=example,dc=com",
		Password:   "123",
		BaseDn:     "ou=BuildIn,dc=example,dc=com",
		AutoSync:   0,
		LastSync:   "",
	}
	_, err = AddLdap(ldap)
	if err != nil {
		panic(err)
	}
}

func initBuiltInProvider() {
	provider, err := GetProvider(util.GetId("grace", "provider_captcha_default"))
	if err != nil {
		panic(err)
	}

	if provider != nil {
		return
	}

	provider = &Provider{
		Owner:       "grace",
		Name:        "provider_captcha_default",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Captcha Default",
		Category:    "Captcha",
		Type:        "Default",
	}
	_, err = AddProvider(provider)
	if err != nil {
		panic(err)
	}
}

func initWebAuthn() {
	gob.Register(webauthn.SessionData{})
}

func initBuiltInUserModel() {
	model, err := GetModel("Nzhinusoft/user-model-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if model != nil {
		return
	}

	model = &Model{
		Owner:       "Nzhinusoft",
		Name:        "user-model-Nzhinusoft",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "Nzhinusoft Model",
		ModelText: `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`,
	}
	_, err = AddModel(model)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApiModel() bool {
	model, err := GetModel("Nzhinusoft/api-model-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if model != nil {
		return true
	}

	modelText := `[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName

[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.subOwner == p.subOwner || p.subOwner == "*") && \
    (r.subName == p.subName || p.subName == "*" || r.subName != "anonymous" && p.subName == "!anonymous") && \
    (r.method == p.method || p.method == "*") && \
    (r.urlPath == p.urlPath || p.urlPath == "*") && \
    (r.objOwner == p.objOwner || p.objOwner == "*") && \
    (r.objName == p.objName || p.objName == "*") || \
    (r.subOwner == r.objOwner && r.subName == r.objName)`

	model = &Model{
		Owner:       "Nzhinusoft",
		Name:        "api-model-Nzhinusoft",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "API Model",
		ModelText:   modelText,
	}
	_, err = AddModel(model)
	if err != nil {
		panic(err)
	}
	return false
}

func initBuiltInPermission() {
	permission, err := GetPermission("Nzhinusoft/permission-Nzhinusoft")
	if err != nil {
		panic(err)
	}
	if permission != nil {
		return
	}

	permission = &Permission{
		Owner:        "Nzhinusoft",
		Name:         "permission-Nzhinusoft",
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  "Nzhinusoft Permission",
		Description:  "Nzhinusoft Permission",
		Users:        []string{"Nzhinusoft/*"},
		Groups:       []string{},
		Roles:        []string{},
		Domains:      []string{},
		Model:        "user-model-Nzhinusoft",
		Adapter:      "",
		ResourceType: "Application",
		Resources:    []string{"app-Nzhinusoft"},
		Actions:      []string{"Read", "Write", "Admin"},
		Effect:       "Allow",
		IsEnabled:    true,
		Submitter:    "grace",
		Approver:     "grace",
		ApproveTime:  util.GetCurrentTime(),
		State:        "Approved",
	}
	_, err = AddPermission(permission)
	if err != nil {
		panic(err)
	}
}

func initBuiltInUserAdapter() {
	adapter, err := GetAdapter("Nzhinusoft/user-adapter-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if adapter != nil {
		return
	}

	adapter = &Adapter{
		Owner:       "Nzhinusoft",
		Name:        "user-adapter-Nzhinusoft",
		CreatedTime: util.GetCurrentTime(),
		Table:       "casbin_user_rule",
		UseSameDb:   true,
	}
	_, err = AddAdapter(adapter)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApiAdapter() {
	adapter, err := GetAdapter("Nzhinusoft/api-adapter-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if adapter != nil {
		return
	}

	adapter = &Adapter{
		Owner:       "Nzhinusoft",
		Name:        "api-adapter-Nzhinusoft",
		CreatedTime: util.GetCurrentTime(),
		Table:       "casbin_api_rule",
		UseSameDb:   true,
	}
	_, err = AddAdapter(adapter)
	if err != nil {
		panic(err)
	}
}

func initBuiltInUserEnforcer() {
	enforcer, err := GetEnforcer("Nzhinusoft/user-enforcer-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if enforcer != nil {
		return
	}

	enforcer = &Enforcer{
		Owner:       "Nzhinusoft",
		Name:        "user-enforcer-Nzhinusoft",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "User Enforcer",
		Model:       "Nzhinusoft/user-model-Nzhinusoft",
		Adapter:     "Nzhinusoft/user-adapter-Nzhinusoft",
	}

	_, err = AddEnforcer(enforcer)
	if err != nil {
		panic(err)
	}
}

func initBuiltInApiEnforcer() {
	enforcer, err := GetEnforcer("Nzhinusoft/api-enforcer-Nzhinusoft")
	if err != nil {
		panic(err)
	}

	if enforcer != nil {
		return
	}

	enforcer = &Enforcer{
		Owner:       "Nzhinusoft",
		Name:        "api-enforcer-Nzhinusoft",
		CreatedTime: util.GetCurrentTime(),
		DisplayName: "API Enforcer",
		Model:       "Nzhinusoft/api-model-Nzhinusoft",
		Adapter:     "Nzhinusoft/api-adapter-Nzhinusoft",
	}

	_, err = AddEnforcer(enforcer)
	if err != nil {
		panic(err)
	}
}

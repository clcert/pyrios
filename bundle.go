// Copyright 2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pyrios

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"

	"github.com/golang/glog"
)

// An ElectionBundle captures all the information needed to verify a Helios
// election. Since there is no secret information here, this data structure can
// be exported and served as JSON from arbitrary websites as long as the
// verifier knows the election fingerprint and trustee fingerprints for the
// election they want to verify. The values are kept as uninterpreted bytes to
// make sure they don't do round trips through other JSON interpreters.
type ElectionBundle struct {
	ElectionData []byte   `json:"election"`
	VotersData   [][]byte `json:"voters"`
	VotesData    [][]byte `json:"votes"`
	ResultsData  []byte   `json:"results"`
	TrusteesData []byte   `json:"trustees"`

	Election *Election     `json:"-"`
	Voters   []*Voter      `json:"-"`
	Votes    []*CastBallot `json:"-"`
	Results  Result        `json:"-"`
	Trustees []*Trustee    `json:"-"`
}

// Instantiate deserializes the serialized election data structures (the *Data
// values) stored in an ElectionBundle.
func (b *ElectionBundle) Instantiate() error {
	// This prepares the election hash that is used in cast-ballot verification.
	err := UnmarshalJSON(b.ElectionData, &b.Election)
	if err != nil {
		return err
	}

	b.Election.Init(b.ElectionData)

	for i, jsonData := range b.VotersData {
		var tempVoters []*Voter
		err = UnmarshalJSON(jsonData, &tempVoters)
		if err != nil {
			glog.Errorf("Couldn't unmarshal the voter information for set %d\n", i)
			return err
		}

		b.Voters = append(b.Voters, tempVoters...)
	}

	glog.Infof("There are %d voters in this election\n", len(b.Voters))

	for i, jsonData := range b.VotesData {
		var vote *CastBallot
		err = UnmarshalJSON(jsonData, &vote)
		if err != nil {
			glog.Error("Couldn't unmarshal voter ", i)
			return err
		}

		vote.JSON = jsonData
		b.Votes = append(b.Votes, vote)
	}

	glog.Infof("Collected %d cast ballots for the retally\n", len(b.Votes))

	// The trustee information is a list of Trustees.
	if err = UnmarshalJSON(b.TrusteesData, &b.Trustees); err != nil {
		glog.Error("Couldn't unmarshal the trustees")
		return err
	}

	if err = UnmarshalJSON(b.ResultsData, &b.Results); err != nil {
		glog.Info("Couldn't unmarshal the result of the election")
	}

	return nil
}

// Download gets an election bundle from the helios server using the given
// election uuid. Username and password are required to login to Helios server
// if the election is private.
func Download(server string, uuid string, username, password string) (*ElectionBundle, error) {
	elecAddr := server + "app/elections/" + uuid
	b := new(ElectionBundle)

	client := http.DefaultClient
	var err error
	if username != "" && password != "" {
		client, err = getLoggedInClient(server, username, password)
		if err != nil {
			glog.Error("Couldn't log in: ", err)
			return nil, err
		}
	}

	if b.ElectionData, err = GetJSON(elecAddr, &b.Election, client); err != nil {
		glog.Error("Couldn't get the election data: ", err)
		return nil, err
	}

	b.Election.Init(b.ElectionData)

	// The helios server times out if it tries to return too many voters at
	// once.  This can be a problem for large elections (like the annual
	// IACR elections).  So, it provides a limit parameter and an after
	// parameter. The limit parameter specifies the maximum number of
	// voters to return, and the after parameter
	// specifies the last received voter.
	after := ""
	for {
		var tempVoters []*Voter
		var votersJSON []byte
		// Helios accepts "after=" as specifying the beginning of the
		// list.
		addr := elecAddr + "/voters/?after=" + after + "&limit=100"
		votersJSON, err = GetJSON(addr, &tempVoters, client)
		if err != nil {
			glog.Error("Couldn't get the voter information")
			return nil, err
		}

		// Helios returns an empty array when there are no more voters.
		if len(tempVoters) == 0 {
			break
		}

		b.Voters = append(b.Voters, tempVoters...)
		b.VotersData = append(b.VotersData, votersJSON)

		after = tempVoters[len(tempVoters)-1].Uuid
		glog.Info("Got ", len(tempVoters), " voters")
	}

	glog.Infof("There are %d voters in this election\n", len(b.Voters))

	for _, v := range b.Voters {
		glog.Info("Getting voter ", v.Uuid)
		var vote *CastBallot
		jsonData, err := GetJSON(elecAddr+"/ballots/"+v.Uuid+"/last", &vote, client)
		if err != nil {
			glog.Errorf("Couldn't get the last ballot cast by %s\n", v.Uuid)
		}

		// Skip ballots that weren't ever cast.
		if len(vote.CastAt) == 0 {
			continue
		}

		vote.JSON = jsonData
		b.Votes = append(b.Votes, vote)
		b.VotesData = append(b.VotesData, jsonData)
	}

	glog.Info("Collected ", len(b.Votes), " cast ballots for the retally")

	// The trustee information is a list of Trustees.
	if b.TrusteesData, err = GetJSON(elecAddr+"/trustees/", &b.Trustees, client); err != nil {
		glog.Error("Couldn't get the list of trustees: ", err)
		return nil, err
	}

	if b.ResultsData, err = GetJSON(elecAddr+"/result", &b.Results, client); err != nil {
		glog.Info("Couldn't get the result of the election: ", err)
		// Let the result be null if we can't get it. Helios will warn
		// about this later.
	}

	return b, nil
}

// Verify checks that the given election bundle passes retally verification.
func (b *ElectionBundle) Verify() bool {
	return b.Election.Retally(b.Votes, b.Results, b.Trustees)
}

func getLoggedInClient(server, username, password string) (*http.Client, error) {
	loginUrl := server + "auth/password/login"
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
	}

	csrfResponse, err := client.Get(loginUrl)
	if err != nil {
		return nil, err
	}

	defer csrfResponse.Body.Close()
	body, err := ioutil.ReadAll(csrfResponse.Body)
	if err != nil {
		return nil, err
	}

	csrfRegex := regexp.MustCompile("name=\"csrf_token\" value=\"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\"")
	csrfMatches := csrfRegex.FindSubmatch(body)
	if len(csrfMatches) != 2 {
		return nil, fmt.Errorf("unable to find csrf token")
	}
	csrf := string(csrfMatches[len(csrfMatches)-1])

	loginResponse, err := client.PostForm(loginUrl, url.Values{"csrf_token": {csrf}, "username": {username}, "password": {password}})
	if err != nil {
		return nil, err
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode != 200 {
		return nil, fmt.Errorf("wrong username or password")
	}
	return client, nil
}

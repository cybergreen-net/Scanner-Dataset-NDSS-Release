package testing

import (
	"Scanner/pkg/scanner/structs"
	"encoding/json"
	"testing"
)

func TestRequestSerializationAndDeserialization(t *testing.T) {
	hostname := "google.com"
	query := structs.Request{Hostname: hostname}
	serializedQuery, err := json.Marshal(query)
	if err != nil {
		t.Error(err)
	}
	serializedQueryJSONString := string(serializedQuery)

	expectedJSONString := `{"hostname":"google.com","noServer":false}`
	var expectedQuery structs.Request
	err = json.Unmarshal([]byte(expectedJSONString), &expectedQuery)
	if err != nil {
		t.Errorf("Unable to convert JSON string to Request instance. %v\n", err)
	}

	if serializedQueryJSONString != expectedJSONString {
		t.Errorf("Mismatched string serializations. %v != %v\n", serializedQueryJSONString, expectedJSONString)
	}
	if query != expectedQuery {
		t.Errorf("Object data mismatch. %v != %v\n", query, expectedQuery)
	}
}

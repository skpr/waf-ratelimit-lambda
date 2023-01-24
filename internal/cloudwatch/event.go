package cloudwatch

// HasBecomeAlarm will unmarshal the event to determine if it became alarm.
func HasBecomeAlarm(event Event) bool {
	// Check if the alarm has already been triggered.
	if event.Detail.PreviousState.Value == EventDetailStateValueAlarm {
		return false
	}

	// Check if the alarm is NOW in the triggered state.
	if event.Detail.State.Value != EventDetailStateValueAlarm {
		return false
	}

	return true
}

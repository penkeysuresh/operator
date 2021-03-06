package status

import (
	"github.com/stretchr/testify/mock"
	"k8s.io/apimachinery/pkg/types"
)

type MockStatus struct {
	mock.Mock
}

func (m *MockStatus) Run() {
	m.Called()
}

func (m *MockStatus) OnCRFound() {
	m.Called()
}

func (m *MockStatus) OnCRNotFound() {
	m.Called()
}

func (m *MockStatus) AddDaemonsets(dss []types.NamespacedName) {
	m.Called(dss)
}

func (m *MockStatus) AddDeployments(deps []types.NamespacedName) {
	m.Called(deps)
}

func (m *MockStatus) AddStatefulSets(sss []types.NamespacedName) {
	m.Called(sss)
}

func (m *MockStatus) AddCronJobs(cjs []types.NamespacedName) {
	m.Called(cjs)
}

func (m *MockStatus) RemoveDaemonsets(dss ...types.NamespacedName) {
	m.Called(dss)
}

func (m *MockStatus) RemoveDeployments(dps ...types.NamespacedName) {
	m.Called(dps)
}

func (m *MockStatus) RemoveStatefulSets(sss ...types.NamespacedName) {
	m.Called(sss)
}

func (m *MockStatus) RemoveCronJobs(cjs ...types.NamespacedName) {
	m.Called(cjs)
}

func (m *MockStatus) SetDegraded(reason, msg string) {
	m.Called(reason, msg)
}

func (m *MockStatus) ClearDegraded() {
	m.Called()
}

func (m *MockStatus) IsAvailable() bool {
	return m.Called().Bool(0)
}

func (m *MockStatus) IsProgressing() bool {
	return m.Called().Bool(0)
}

func (m *MockStatus) IsDegraded() bool {
	return m.Called().Bool(0)
}

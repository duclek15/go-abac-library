package abac

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
)

// hasFunc kiểm tra xem một giá trị có tồn tại trong một slice hay không.
func hasFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'has' yêu cầu 2 tham số, nhận được %d", len(args))
	}
	sliceVal := reflect.ValueOf(args[0])
	elementVal := reflect.ValueOf(args[1])
	if sliceVal.Kind() != reflect.Slice {
		return false, fmt.Errorf("tham số đầu tiên của hàm 'has' phải là một slice, nhận được %s", sliceVal.Kind())
	}
	for i := 0; i < sliceVal.Len(); i++ {
		if reflect.DeepEqual(sliceVal.Index(i).Interface(), elementVal.Interface()) {
			return true, nil
		}
	}
	return false, nil
}

// intersectsFunc kiểm tra xem hai slice có ít nhất một phần tử chung hay không.
func intersectsFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'intersects' yêu cầu 2 tham số, nhận được %d", len(args))
	}
	slice1 := reflect.ValueOf(args[0])
	slice2 := reflect.ValueOf(args[1])
	if slice1.Kind() != reflect.Slice || slice2.Kind() != reflect.Slice {
		return false, fmt.Errorf("cả hai tham số của hàm 'intersects' phải là slice")
	}
	set := make(map[interface{}]bool)
	for i := 0; i < slice1.Len(); i++ {
		set[slice1.Index(i).Interface()] = true
	}
	for i := 0; i < slice2.Len(); i++ {
		if set[slice2.Index(i).Interface()] {
			return true, nil
		}
	}
	return false, nil
}

// isIpInCidrFunc kiểm tra một địa chỉ IP có nằm trong một dải mạng CIDR hay không.
func isIpInCidrFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'isIpInCidr' yêu cầu 2 tham số")
	}
	ipStr, ok1 := args[0].(string)
	cidrStr, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("tham số của 'isIpInCidr' phải là chuỗi")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, nil
	}
	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false, nil
	}
	return network.Contains(ip), nil
}

// matchesFunc kiểm tra một chuỗi có khớp với một mẫu biểu thức chính quy (Regex) hay không.
func matchesFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'matches' yêu cầu 2 tham số")
	}
	text, ok1 := args[0].(string)
	pattern, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("tham số của 'matches' phải là chuỗi")
	}
	return regexp.MatchString(pattern, text)
}

// isBusinessHoursFunc kiểm tra xem giờ hiện tại có nằm trong giờ hành chính hay không.
func isBusinessHoursFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 3 {
		return false, fmt.Errorf("hàm 'isBusinessHours' yêu cầu 3 tham số: currentTime, startHour, endHour")
	}
	// govaluate thường truyền số dưới dạng float64
	currentTime, ok1 := args[0].(float64)
	startHour, ok2 := args[1].(float64)
	endHour, ok3 := args[2].(float64)
	if !ok1 || !ok2 || !ok3 {
		return false, fmt.Errorf("tham số của 'isBusinessHours' phải là số")
	}
	return currentTime >= startHour && currentTime < endHour, nil
}

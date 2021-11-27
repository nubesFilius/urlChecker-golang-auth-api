package utils

import "errors"

func WordInSlice(lookfor string, sli []string) bool {
	for _, str := range sli {
		if lookfor == str {
			return true
		}
	}
	return false
}

func RemoveStrFromSlice(str string, sli []string) ([]string, error) {
	for idx, elem := range sli {
		if elem == str {
			//if the index is not that of the last
			if idx < len(sli)-1 {
				sli = append(sli[:idx], sli[idx+1:]...)
				return sli, nil
			}
			//if its the last
			sli = sli[:idx]
			return sli, nil
		}
	}
	return nil, errors.New("String Not Found")
}

#pragma once
#include <string>
#include <vector>

enum O4RequestMethods
{
	NONE = 0,
	GET,
	POST,
	DELETE
};

class O4Request
{
public:
	O4Request()
		: method(O4RequestMethods::NONE), request_Line(""), body("") {}

	O4RequestMethods GetRequestMethod() { return method; }
	std::string GetRequestLine() { return request_Line; }
	std::vector<std::string> GetRequestHeader() { return header; }
	std::string GetRequestBody() { return body; }

	void SetRequestMethod(O4RequestMethods req) {method = req;}
	void SetRequestLine(std::string req) {	request_Line = req;	}
	void SetRequestMethod(std::initializer_list<std::string>& head) {header = head;	}
	void SetRequestBody(std::string str) { body = str; }

private:
	O4RequestMethods method;
	std::string request_Line;
	std::vector<std::string> header;
	std::string body;
};
#pragma once
#include "headers.hpp"

namespace k_hook
{
	// �ص�����
	typedef void(__fastcall* fptr_call_back)(unsigned long ssdt_index, void** ssdt_address);

	// ��ʼ������
	bool initialize(fptr_call_back fptr);

	// ��ʼ���غ�������
	bool start();

	// �������غ�������
	bool stop();
}
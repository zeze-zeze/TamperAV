#include "enumCallback.hpp"

VOID ShowError(PCHAR lpszText, NTSTATUS ntStatus)
{
				DbgPrint("%s Error[0x%X]\n", lpszText, ntStatus);
}

//關閉記憶體寫入保護
KIRQL WPOFFx64()
{
				KIRQL irql = KeRaiseIrqlToDpcLevel();
				UINT64 cr0 = __readcr0();
				cr0 &= 0xfffffffffffeffff;
				__writecr0(cr0);
				_disable();
				return irql;
}

//恢復記憶體寫入保護
void WPONx64(KIRQL irql)
{
				UINT64 cr0 = __readcr0();
				cr0 |= 0x10000;
				_enable();
				__writecr0(cr0);
				KeLowerIrql(irql);
}

//patch 地址 , 直接 return 0
VOID PatchedObcallbacks(PVOID Address, LONG index, bool restore)
{
				KIRQL irql;
				CHAR patchCode[] = "\x33\xC0\xC3";	//xor eax,eax + ret
				if (!Address)
								return;
				if (MmIsAddressValid(Address))
				{
								irql = WPOFFx64();//關閉寫入保護
								if (restore) {
												memcpy(Address, originalCode[index], 3);
												DbgPrint("restore 0x%p to 0x%p: 0x%p\n", Address, originalCode[index][0], *(char*)Address);
								}
								else {
												memcpy(originalCode[index], Address, 3);
												DbgPrint("store 0x%p as 0x%p: 0x%p\n", Address, originalCode[index][0], *(char *)Address);
												memcpy(Address, patchCode, 3);
								}
								WPONx64(irql);//恢復寫入保護
				}
}

//列舉 callback (process)
BOOLEAN EnumProcessObCallback(bool restore)
{
				POB_CALLBACK pObCallback = NULL;

				LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsProcessType))->CallbackList;

				pObCallback = (POB_CALLBACK)CallbackList.Flink;
				LONG index = 0;
				do
				{
								if (FALSE == MmIsAddressValid(pObCallback))
								{
												break;
								}
								if (NULL != pObCallback->ObHandle)
								{
												DbgPrint("[PsProcessType]pObCallback->ObHandle = 0x%p\n", pObCallback->ObHandle);
												DbgPrint("[PsProcessType]pObCallback->PreCall = 0x%p\n", pObCallback->PreCall);
												DbgPrint("[PsProcessType]pObCallback->PostCall = 0x%p\n", pObCallback->PostCall);
												//方法一:直接 Remove (卡巴會卡住 system)
												//auto status = RemoveObCallback(pObCallback->ObHandle);
												//if(status == STATUS_SUCCESS)
												//	DbgPrint("[Remove] ObHandle= 0x%p  Success\n", pObCallback->ObHandle);
												//else
												//	DbgPrint("[Remove] ObHandle= 0x%p  Fail\n", pObCallback->ObHandle);
												//方法二: patch PreCall & PostCall , 不處理返回 null
												PatchedObcallbacks(pObCallback->PreCall, index, restore);
												PatchedObcallbacks(pObCallback->PostCall, index+1, restore);
												index += 2;
												DbgPrint("[Patch] pObCallback->PreCall= 0x%p  Success\n", pObCallback->PreCall);

								}
								//下一個 callback
								pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

				} while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);

				return TRUE;
}



//列舉 callback (thread)
BOOLEAN EnumThreadObCallback(bool restore)
{
				POB_CALLBACK pObCallback = NULL;

				LIST_ENTRY CallbackList = ((POBJECT_TYPE)(*PsThreadType))->CallbackList;
				pObCallback = (POB_CALLBACK)CallbackList.Flink;
				LONG index = 100;
				do
				{
								if (FALSE == MmIsAddressValid(pObCallback))//透過 MmIsAddressValid() 檢查地址是否正確.
								{
												break;
								}
								if (NULL != pObCallback->ObHandle)
								{
												DbgPrint("[PsThreadype]pObCallback->ObHandle = 0x%p\n", pObCallback->ObHandle);
												DbgPrint("[PsThreadType]pObCallback->PreCall = 0x%p\n", pObCallback->PreCall);
												DbgPrint("[PsThreadType]pObCallback->PostCall = 0x%p\n", pObCallback->PostCall);
												PatchedObcallbacks(pObCallback->PreCall, index, restore);
												PatchedObcallbacks(pObCallback->PostCall, index+1, restore);
												index += 2;
												DbgPrint("[Remove] pObCallback->PreCall= 0x%p  Success\n", pObCallback->PreCall);
								}
								//下一個
								pObCallback = (POB_CALLBACK)pObCallback->ListEntry.Flink;

				} while (CallbackList.Flink != (PLIST_ENTRY)pObCallback);

				return TRUE;
}

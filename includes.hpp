#pragma once
#define DEG2RAD(x) x * M_PI / 180.0
#define M_PI       3.14159265358979323846
#define DIRECTINPUT_VERSION 0x0800

/* WinApi C++ 17 */
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <winhttp.h>
#include <fstream>
#include <string>
#include <direct.h>
#include <TlHelp32.h>
#include <vector>
#include <process.h>
#include <thread>
#include <bitset>
#include <mutex>
#include <array>
#include <dwmapi.h>
#include <Winternl.h>

/* D3D SDK */
#include <d3d11.h>
#include <DirectXMath.h>
#include <d3d9types.h>

/* Overlay & Imgui */
#include "ImGui/imgui.h"
#include "ImGui/imgui_impl_dx11.h"
#include "ImGui/imgui_impl_win32.h"
#include "ImGui/imgui_internal.h""

/* String Encrypted */
#include "Xor.hpp"

/* Offset & Address */
#include "Offsets.hpp"

/* Config */
#include "Config.hpp"

/* Render */
#include "Vector.hpp"
#include "Renderer.hpp"

#include "IDAdefs.h"

/* Lib */
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")

/* SDK (Memory) */
#include "SDK.hpp"
#pragma warning(disable : 4996)

//namespace fs = std::filesystem;
using namespace DirectX;

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#define OFF_MEMB(type, name, offset)\
struct {\
    char zpad##name[offset];\
    type name;\
}\

namespace OW {
	auto viewMatrixVal = SDK->RPM<uint64_t>(SDK->dwGameBase + offset::Address_viewmatrix_base) ^ offset::offset_viewmatrix_xor_key;
	Vector2 WindowSize = SDK->RPM<Vector2>(viewMatrixVal + 0x424);
	float WX = WindowSize.X;
	float WY = WindowSize.Y;

	inline Matrix viewMatrix = {};
	inline Matrix viewMatrix_xor = {};
	inline uint64_t viewMatrixPtr = {};
	inline uint64_t viewMatrix_xor_ptr = {};

	enum eTeam
	{
		TEAM_RED,
		TEAM_BLUE,
		TEAM_UNKNOWN1,
		TEAM_UNKNOWN2,
		TEAM_DEATHMATCH,
	};

	enum BONE : int {
		BONE_HEAD = 17,
		BONE_NECK = 16,
		BONE_CHEST = 2,
		BONE_R_KNEE = 99,
		BONE_R_SHANK = 97,
		BONE_R_ANKLE = 96,
		BONE_R_SHOULDER = 54,
		BONE_R_ELBOW = 51,
		BONE_R_HAND = 71,
		BONE_L_KNEE = 89,
		BONE_L_SHANK = 87,
		BONE_L_ANKLE = 86,
		BONE_L_SHOULDER = 49,
		BONE_L_ELBOW = 14,
		BONE_L_HAND = 41,
		BONE_PELVIS = 3,
		BONE_BODY = 81,
		BONE_BODY_BOT = 82,
	};

	enum eHero : uint64_t
	{

		HERO_REAPER = 0x2E0000000000002,
		HERO_TRACER = 0x2E0000000000003,
		HERO_MERCY = 0x2E0000000000004,
		HERO_HANJO = 0x2E0000000000005,
		HERO_TORBJORN = 0x2E0000000000006,
		HERO_REINHARDT = 0x2E0000000000007,
		HERO_PHARAH = 0x2E0000000000008,
		HERO_WINSTON = 0x2E0000000000009,
		HERO_WIDOWMAKER = 0x2E000000000000A,
		HERO_BASTION = 0x2E0000000000015,
		HERO_SYMMETRA = 0x2E0000000000016,
		HERO_ZENYATTA = 0x2E0000000000020,
		HERO_GENJI = 0x2E0000000000029,
		HERO_ROADHOG = 0x2E0000000000040,
		HERO_CASSIDY = 0x2E0000000000042,
		HERO_JUNKRAT = 0x2E0000000000065,
		HERO_ZARYA = 0x2E0000000000068,
		HERO_SOLDIER76 = 0x2E000000000006E,
		HERO_LUCIO = 0x2E0000000000079,
		HERO_DVA = 0x2E000000000007A,
		HERO_MEI = 0x2E00000000000DD,
		HERO_ANA = 0x2E000000000013B,
		HERO_SOMBRA = 0x2E000000000012E,
		HERO_ORISA = 0x2E000000000013E,
		HERO_DOOMFIST = 0x2E000000000012F,
		HERO_MOIRA = 0x2E00000000001A2,
		HERO_BRIGITTE = 0x2E0000000000195,
		HERO_WRECKINGBALL = 0x2E00000000001CA,
		HERO_SOJOURN = 0x2E00000000001EC,
		HERO_ASHE = 0x2E0000000000200,
		HERO_BAPTISTE = 0x2E0000000000221,
		HERO_KIRIKO = 0x2E0000000000231,
		HERO_JUNKERQUEEN = 0x2E0000000000236,
		HERO_SIGMA = 0x2E000000000023B,
		HERO_ECHO = 0x2E0000000000206,
		HERO_RAMATTRA = 0x2E000000000028D,
		HERO_LIFEWEAVER = 0x02E0000000000291,
		HERO_TRAININGBOT1 = 0x2e000000000033c,
		HERO_TRAININGBOT2 = 0x2E0000000000337,
		HERO_TRAININGBOT3 = 0x2E000000000035a,
		HERO_TRAININGBOT4 = 0x2E000000000016c,
		HERO_TRAININGBOT5 = 0x2E0000000000363,
		HERO_TRAININGBOT6 = 0x2E0000000000349,
		HERO_ILLARI = 0x02e000000000031c,
	};

	enum eComponentType
	{
		TYPE_ERROR = -1,
		TYPE_VELOCITY = 0x4,
		TYPE_TEAM = 0x21,
		TYPE_NAME = 0x25,
		TYPE_BONE = 0x27,
		TYPE_ROTATION = 0x2F,
		TYPE_LINK = 0x34,
		TYPE_P_VISIBILITY = 0x35,
		TYPE_SKILL = 0x37,
		TYPE_ANGLE = 0x39,
		TYPE_HEALTH = 0x3B,
		TYPE_PLAYERCONTROLLER = 0x43,
		TYPE_P_HEROID = 0x54,
		TYPE_OUTLINE = 0x5B,
	};

	const char* keys = ("VK_XBUTTON2");
	const char* key_type[] = { ("VK_LBUTTON"), ("VK_RBUTTON"),  ("VK_MBUTTON"),  ("VK_XBUTTON1"),  ("VK_XBUTTON2") };

	struct espBone {
		bool boneerror = false;
		Vector2 upL, upR, downL, downR;

		Vector2 head, neck, body_1, body_2, l_1, l_2, r_1, r_2, l_d_1, l_d_2, r_d_1, r_d_2, l_a_1, l_a_2, r_a_1, r_a_2, sex, sex1, sex2, sex3;
	};

	class c_entity
	{
	public:
		DWORD_PTR address;
		DWORD_PTR LinkBase;
		DWORD_PTR HealthBase;
		DWORD_PTR TeamBase;
		DWORD_PTR VelocityBase;
		DWORD_PTR HeroBase;
		DWORD_PTR BoneBase;
		DWORD_PTR OutlineBase;
		DWORD_PTR SkillBase;
		DWORD_PTR RotationBase;
		DWORD_PTR VisBase;
		DWORD_PTR AngleBase;
		DWORD_PTR EnemyAngleBase;
		DWORD_PTR ObjectBase;
		DWORD_PTR NameBase;
		DWORD_PTR HeroID;
		uint32_t PlayerID;
		uint16_t Dva;

		uint32_t BorderType;
		uint32_t BorderColor;

		char* HeroName;
		char* BattleTag;
		char* PlayerName;

		int head_index = 0;

		float PlayerHealth = 0.f;
		float PlayerHealthMax = 0.f;
		float MinHealth = 0.f;
		float MaxHealth = 0.f;
		float MinArmorHealth = 0.f;
		float MaxArmorHealth = 0.f;
		float MinBarrierHealth = 0.f;
		float MaxBarrierHealth = 0.f;
		float ULT = 0.f;
		bool Alive;
		bool Vis;
		bool Team;
		bool Trg;

		c_entity() : address(0) {};
		c_entity(uint64_t _UniqueID) : address(address) {};
		__forceinline bool operator==(const c_entity& entity) const
		{
			return (this->address == entity.address);
		}
		__forceinline bool operator!=(const c_entity& entity) const
		{
			return (this->address != entity.address);
		}

		eTeam GetTeam()
		{
			uint32_t Team = SDK->RPM<uint32_t>(this->TeamBase + 0x58) & 0x0F800000;
			std::bitset<sizeof(int)* CHAR_BIT> bitTeam(Team);
			if (bitTeam[0x17])
				return eTeam::TEAM_RED;
			else if (bitTeam[0x18])
				return eTeam::TEAM_BLUE;
			else if (bitTeam[0x19])
				return eTeam::TEAM_UNKNOWN1;
			else if (bitTeam[0x1A])
				return eTeam::TEAM_UNKNOWN2;
			else if (bitTeam[0x1B])
				return eTeam::TEAM_DEATHMATCH;
		}

		uint64_t __fastcall get_outline_struct(__int64 a1) //40 53 48 83 EC 30 65 48 8B 04 25 ? ? ? ? 48
		{
			__int64 v2; // rcx
			int v4; // er9
			v2 = SDK->RPM<int>(a1 + 0x68);
			if ((_DWORD)v2)
				return  (uint64_t)(0x20 * v2 + SDK->RPM<_QWORD>(a1 + 0x60) - 0x20i64);
			else
				return 0i64;
		}

		uint64_t __fastcall get_color_struct(__int64 a1) //40 57 48 83 EC 20 44 8B 91
		{
			__int64 v2; // rax

			v2 = SDK->RPM<int>(a1 + 0xF8);
			if ((_DWORD)v2)
				return (SDK->RPM<_QWORD>(a1 + 0xF0) + 0x14 * v2 - 0x14);
			else
				return 0i64;
		}

		uint64_t __fastcall decrypt_outline_xor(__int64 a1)
		{
			__int64 v1; // rbx
			unsigned __int64 v2; // rdi
			unsigned __int64 v3; // rax
			__int64 v4; // rbx
			unsigned __int64 v5; // rdx
			unsigned __int64 v6; // rcx
			__m128i v7; // xmm1
			__m128i v8; // xmm2
			__m128i v9; // xmm0
			__m128i v10; // xmm1

			v2 = SDK->dwGameBase + offset::Outline_Fn;
			v3 = v2 + 0x8;

			uint64_t keys = SDK->dwGameBase + 0x3720340 + 8 * (((_BYTE)a1 - 0x76) & 0x7F);
			v4 = v2 ^ SDK->RPM<DWORD_PTR>(keys
				+ (((unsigned __int64)(a1 - offset::Outline_Key) >> 7) & 7)) ^ (a1 - offset::Outline_Key);

			v5 = (v3 - v2 + 7) >> 3;
			v6 = 0i64;
			if (v2 > v3)
				v5 = 0i64;
			if (v5)
			{
				if (v5 >= 4)
				{
					v7 = {};
					v8 = {};
					do
					{
						v6 += 4i64;
						v7 = _mm_xor_si128(v7, _mm_loadu_si128((const __m128i*)v2));
						v9 = _mm_loadu_si128((const __m128i*)(v2 + 16));
						v2 += 0x20i64;
						v8 = _mm_xor_si128(v8, v9);
					} while (v6 < (v5 & 0xFFFFFFFFFFFFFFFCui64));
					v10 = _mm_xor_si128(v7, v8);
					__m128i P1 = _mm_xor_si128(v10, _mm_srli_si128(v10, 8));
					v4 ^= *(DWORD_PTR*)&P1;
				}
				for (; v6 < v5; ++v6)
				{
					v4 ^= SDK->RPM<DWORD_PTR>(v2);
					v2 += 8i64;
				}
			}
			return v4 ^ ~v3 ^ 0x0B156B2D970B05A8A;
		}


		void SetBorderLine(uint32_t BorderType, uint32_t BorderColor)
		{
			if (BorderType) {
				uint64_t BorderStruct = get_outline_struct((uint64_t)this->OutlineBase + 0x20);
				uint64_t DecryptData = decrypt_outline_xor(SDK->RPM<uint64_t>(BorderStruct + 0x18));
				uint32_t data = DecryptData ^ BorderType;
				SDK->WPM<uint32_t>(BorderStruct + 0x10, data);
			}

			if (BorderColor)
			{
				uint64_t Color = get_color_struct(this->OutlineBase + 0x20);
				SDK->WPM<uint32_t>(Color + 0x10, BorderColor);
			}
		}


		int get_bone_id(uint64_t bonedata, int bone_id) {
			__try {
				uint32_t* v1 = (uint32_t*)SDK->RPM<uint64_t>(SDK->RPM<uint64_t>(bonedata) + 0x38);
				uint16_t count = SDK->RPM <uint16_t>(SDK->RPM <uint64_t>(bonedata) + 0x66);
				for (int i = 0; i < count; i++) {
					if (SDK->RPM<uint16_t>((uint64_t)(v1 + i)) == bone_id) {
						return i;
					}
				}
			}
			__except (1) {

			}
		}

		Vector3 GetBonePos(int index) {
			__try {
				if (this->pos != Vector3(0, 0, 0) && this->PlayerHealth > 0) 
				{
					uint64_t pBoneData = SDK->RPM<uint64_t>(this->VelocityBase + 0x870);
					if (pBoneData)
					{
						uint64_t bonesBase = SDK->RPM<uint64_t>(pBoneData + 0x20);
						if (bonesBase)
						{
							DirectX::XMFLOAT3 currentBone = SDK->RPM<DirectX::XMFLOAT3>(bonesBase + (0x30 * get_bone_id(pBoneData, index)) + 0x20);
							DirectX::XMFLOAT3 Result{};
							XMMATRIX rotMatrix = XMMatrixRotationY(this->Rot.X/*-atan2(this->Rot.Z, this->Rot.X)*/);
							DirectX::XMStoreFloat3(&Result, XMVector3Transform(XMLoadFloat3(&currentBone), rotMatrix));
							return Vector3(Result.x, Result.y, Result.z) + this->pos;
						}
					}
				}
				return Vector3{};
			}
			__except (1) {
				return Vector3{};
			}
		}

		std::array<int, 18> GetSkel() {
			switch (this->HeroID) {
			case eHero::HERO_ANA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_ASHE:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_BAPTISTE:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_BASTION:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, 85, 95, 89, 99, BONE_L_HAND, 156};
			case eHero::HERO_BRIGITTE:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_DOOMFIST:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_DVA:
				if (SDK->RPM<uint16_t>(this->LinkBase + 0xD4) != SDK->RPM<uint16_t>(this->LinkBase + 0xD8))
					return std::array<int, 18>{BONE_HEAD, BONE_NECK, 4, BONE_BODY_BOT, 80, 53, 27, 57, 85, 95, 89, 99, 153, 154};
				else
					return std::array<int, 18>{BONE_HEAD, 16, 81, 82, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_ECHO:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_GENJI:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_HANJO:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_JUNKRAT:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_LUCIO:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_CASSIDY:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_MEI:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, 56, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, 70, 99, 89, 100, 90};
			case eHero::HERO_MERCY:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_MOIRA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_ORISA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, 56, 85, 95, 92, 102, BONE_L_HAND, 58, 99, 89, 100, 90};
			case eHero::HERO_PHARAH:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_REAPER:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_REINHARDT:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_ROADHOG:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_SIGMA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_SOLDIER76:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_SOMBRA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_SYMMETRA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_TORBJORN:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, 28, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_TRACER:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_WIDOWMAKER:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_WINSTON:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_WRECKINGBALL:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_ZARYA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			case eHero::HERO_ZENYATTA:
				return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
			}
			return std::array<int, 18>{BONE_HEAD, BONE_NECK, BONE_BODY, BONE_BODY_BOT, BONE_L_SHOULDER, BONE_R_SHOULDER, BONE_L_ELBOW, BONE_R_ELBOW, BONE_L_ANKLE, BONE_R_ANKLE, BONE_L_SHANK, BONE_R_SHANK, BONE_L_HAND, BONE_R_HAND, 99, 89, 100, 90};
		}

		espBone getBoneList(std::array<int, 18> index) {
			__try {
				espBone a{};
				Vector2 pmin{}, pmax{};
				Vector2 w2s{};
				Vector3 root = this->pos;
				if (this->HeroID == eHero::HERO_TRAININGBOT1 || this->HeroID == eHero::HERO_TRAININGBOT2 || this->HeroID == eHero::HERO_TRAININGBOT3 || this->HeroID == eHero::HERO_TRAININGBOT4) {
					if (viewMatrix.WorldToScreen(root, &w2s, Vector2(WX, WY))) {
						pmin = w2s;
						pmax = w2s;
					}
					else { a.boneerror = true; }
					int index[] = { 17,16,3,13,54 };
					for (int i = 0; i < 5; i++) {
						Vector3 bone = GetBonePos(index[i]);
						Vector2 w2s{};
						if (viewMatrix.WorldToScreen(bone, &w2s, Vector2(WX, WY))) {
							if (i == 0) { a.head = w2s; a.head.Y += 4.f; }
							else if (i == 1) { a.neck = w2s; }
							else if (i == 2) { a.body_1 = w2s; }
							else if (i == 3) { a.l_1 = w2s; }
							else if (i == 4) { a.r_1 = w2s; }
							if (w2s.X < pmin.X) {
								pmin.X = w2s.X;
							}
							if (w2s.Y < pmin.Y) {
								pmin.Y = w2s.Y;
							}
							if (w2s.X > pmax.X) {
								pmax.X = w2s.X;
							}
							if (w2s.Y > pmax.Y) {
								pmax.Y = w2s.Y;
							}
						}
						else { a.boneerror = true; }
					}
					a.upL = pmin;
					a.upR = Vector2(pmax.X, pmin.Y);
					a.downL = Vector2(pmin.X, pmax.Y);
					a.downR = pmax;
					return a;
				}
				else {
					if (viewMatrix.WorldToScreen(root, &w2s, Vector2(WX, WY))) {
						pmin = w2s;
						pmax = w2s;
					}
					else { a.boneerror = true; }
					for (int i = 0; i < 18; i++) {
						Vector3 bone = GetBonePos(index[i]);
						Vector2 w2s{};
						if (viewMatrix.WorldToScreen(bone, &w2s, Vector2(WX, WY))) {
							if (i == 0) { a.head = w2s; }
							else if (i == 1) { a.neck = w2s; }
							else if (i == 2) { a.body_1 = w2s; }
							else if (i == 3) { a.body_2 = w2s; }
							else if (i == 4) { a.l_1 = w2s; }
							else if (i == 5) { a.r_1 = w2s; }
							else if (i == 6) { a.l_d_1 = w2s; }
							else if (i == 7) { a.r_d_1 = w2s; }
							else if (i == 8) { a.l_a_1 = w2s; }
							else if (i == 9) { a.r_a_1 = w2s; }
							else if (i == 10) { a.l_a_2 = w2s; }
							else if (i == 11) { a.r_a_2 = w2s; }
							else if (i == 12) { a.l_d_2 = w2s; }
							else if (i == 13) { a.r_d_2 = w2s; }
							else if (i == 14) { a.sex = w2s; }
							else if (i == 15) { a.sex1 = w2s; }
							else if (i == 16) { a.sex2 = w2s; }
							else if (i == 17) { a.sex3 = w2s; }
							if (w2s.X < pmin.X) {
								pmin.X = w2s.X;
							}
							if (w2s.Y < pmin.Y) {
								pmin.Y = w2s.Y;
							}
							if (w2s.X > pmax.X) {
								pmax.X = w2s.X;
							}
							if (w2s.Y > pmax.Y) {
								pmax.Y = w2s.Y;
							}
						}
						else { a.boneerror = true; }
					}
				}
				a.upL = pmin;
				a.upR = Vector2(pmax.X, pmin.Y);
				a.downL = Vector2(pmin.X, pmax.Y);
				a.downR = pmax;
				return a;
			}
			__except (1) {

			}
		}

		Vector3 head_pos{}, velocity{}, Rot{}, pos{};
	};

	inline std::vector<std::pair<uint64_t, uint64_t>>ow_entities = {};
	inline std::vector<std::pair<uint64_t, uint64_t>>last_ow_entities = {};

	inline std::vector<c_entity> entities = {};
	inline c_entity local_entity = {};
	inline UINT g_Width = {}, g_Height = {};

	// Data
	static ID3D11Device* g_pd3dDevice = NULL;
	static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
	static IDXGISwapChain* g_pSwapChain = NULL;
	static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

	inline void CleanupRenderTarget()
	{
		if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
	}

	inline void CleanupDeviceD3D()
	{
		CleanupRenderTarget();
		if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
		if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
		if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
	}

	inline void CreateRenderTarget()
	{
		ID3D11Texture2D* pBackBuffer;
		g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
		g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
		pBackBuffer->Release();
	}

	inline bool CreateDeviceD3D(HWND hWnd)
	{
		// Setup swap chain
		DXGI_SWAP_CHAIN_DESC sd;
		ZeroMemory(&sd, sizeof(sd));
		sd.BufferCount = 2;
		sd.BufferDesc.Width = 0;
		sd.BufferDesc.Height = 0;
		sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		sd.BufferDesc.RefreshRate.Numerator = 60;
		sd.BufferDesc.RefreshRate.Denominator = 1;
		sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
		sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		sd.OutputWindow = hWnd;
		sd.SampleDesc.Count = 1;
		sd.SampleDesc.Quality = 0;
		sd.Windowed = TRUE;
		sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

		UINT createDeviceFlags = 0;
		//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
		D3D_FEATURE_LEVEL featureLevel;
		const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
		if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
			return false;

		CreateRenderTarget();
		return true;
	}

	// Win32 message handler
	inline LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
			return true;

		switch (msg)
		{
		case WM_SIZE:
			if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
			{
				CleanupRenderTarget();
				g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
				CreateRenderTarget();
			}
			return 0;
		case WM_SYSCOMMAND:
			if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
				return 0;
			break;
		case WM_DESTROY:
			::PostQuitMessage(0);
			return 0;
		}
		return ::DefWindowProc(hWnd, msg, wParam, lParam);
	}
}
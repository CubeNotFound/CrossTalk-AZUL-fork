class ClientError(Exception):
	pass

class ServerError(Exception):
	pass

class GroupNameTooLong(ClientError):
	pass

class GroupDoesNotExist(ClientError):
	pass

class GroupAlreadyExists(ClientError):
	pass

class CannotRemoveSpecialGroup(ClientError):
	pass

class ContactDoesNotExist(ClientError):
	pass

class ContactAlreadyOnContactList(ClientError):
	pass

class NicknameExceedsLengthLimit(ClientError):
	pass

class SpecialMessageNotSentWithDType(ClientError):
	pass

class EmptyDomainInXXL(ClientError):
	pass

class InvalidXXLPayload(ClientError):
	pass

class ContactNotOnContactList(ClientError):
	pass

class UserDoesNotExist(ClientError):
	pass

class ContactNotOnline(ClientError):
	pass

class AuthFail(ClientError):
	pass

class NotAllowedWhileHDN(ClientError):
	pass

class NotAllowedToJoinCircle(ClientError):
	pass

class MemberDoesntHaveSufficientCircleRole(ClientError):
	pass

class CircleDoesNotExist(ClientError):
	pass

class MemberAlreadyInCircle(ClientError):
	pass

class MemberAlreadyInvitedToCircle(ClientError):
	pass

class CircleMemberIsPending(ClientError):
	pass

class CantLeaveCircle(ClientError):
	pass

class MemberNotInCircle(ClientError):
	pass

class ContactListIsFull(ClientError):
	pass

class DataTooLargeToSend(ServerError):
	pass

class MemberIsSuspended(ClientError):
	pass

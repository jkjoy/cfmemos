import { useUserV1Store } from "@/store/v1";
import { User } from "@/types/proto/api/v2/user_service";

const useCurrentUser = () => {
  return useUserV1Store((state) => state.currentUser as User);
};

export default useCurrentUser;

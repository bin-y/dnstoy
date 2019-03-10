#ifndef DNSTOY_SHARED_OBJECT_POOL_H_
#define DNSTOY_SHARED_OBJECT_POOL_H_
#include <memory>
#include <stack>
#include <type_traits>

namespace dnstoy {

template <typename T>
class has_on_recycled_by_object_pool_method {
 private:
  template <typename C>
  static std::true_type test(
      decltype(std::declval<C>().on_recycled_by_object_pool())*);

  template <typename C>
  static std::false_type test(...);

 public:
  static constexpr auto value =
      std::is_same_v<std::true_type, decltype(test<T>(nullptr))>;
};

template <typename T>
inline constexpr bool has_on_recycled_by_object_pool_method_v =
    has_on_recycled_by_object_pool_method<T>::value;

enum class SharedObjectPoolObjectCreationMethod {
  Direct,
  CreateFunctionReturningRawPointer,
  CreateAndCreateWithDeleterFunctionReturningSharedPointer
};

// thread-unsafe, designed for thread_local
template <typename ObjectType, size_t PoolSizePerThread,
          SharedObjectPoolObjectCreationMethod ObjectCreationMethod =
              SharedObjectPoolObjectCreationMethod::Direct>
class SharedObjectPool {
 public:
  using pointer = std::shared_ptr<ObjectType>;
  using weak_pointer = std::weak_ptr<ObjectType>;
  using pool_instance_type =
      SharedObjectPool<ObjectType, PoolSizePerThread, ObjectCreationMethod>;
  using deleter_type = std::function<void(ObjectType*)>;

  template <typename... _Args>
  pointer get_object(_Args&&... args) {
    if (!pool_.empty()) {
      // pool available, ignore args and return object in pool
      auto raw_pointer = pool_.top();
      pool_.pop();
      return pointer(raw_pointer, deleter_);
    }
    // non of object in pool is available
    if (size_ < PoolSizePerThread) {
      // pool is not full, create shared_ptr with deleter
      if constexpr (ObjectCreationMethod ==
                    SharedObjectPoolObjectCreationMethod::Direct) {
        return pointer(new ObjectType(std::forward<_Args>(args)...), deleter_);
      } else if constexpr (ObjectCreationMethod ==
                           SharedObjectPoolObjectCreationMethod::
                               CreateFunctionReturningRawPointer) {
        return pointer(ObjectType::create(std::forward<_Args>(args)...),
                       deleter_);
      } else {
        static_assert(
            ObjectCreationMethod ==
                SharedObjectPoolObjectCreationMethod::
                    CreateAndCreateWithDeleterFunctionReturningSharedPointer,
            "");
        return ObjectType::create_with_deleter(std::forward<_Args>(args)...,
                                               deleter_);
      }
    }
    // pool is full, create shared_ptr without deleter
    if constexpr (ObjectCreationMethod ==
                  SharedObjectPoolObjectCreationMethod::Direct) {
      return pointer(new ObjectType(std::forward<_Args>(args)...));
    } else {
      return ObjectType::create(std::forward<_Args>(args)...);
    }
  }

  static pool_instance_type& get() {
    static thread_local pool_instance_type instance;
    return instance;
  }

 private:
  size_t size_ = 0;
  std::stack<ObjectType*> pool_;
  deleter_type deleter_;

  SharedObjectPool()
      : deleter_(std::bind(&SharedObjectPool::recycle, this,
                           std::placeholders::_1)){};
  void recycle(ObjectType* object) {
    if constexpr (has_on_recycled_by_object_pool_method_v<ObjectType>) {
      object->on_recycled_by_object_pool();
    }
    pool_.push(object);
  }
};

}  // namespace dnstoy
#endif  // DNSTOY_SHARED_OBJECT_POOL_H_